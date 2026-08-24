<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\application\port\PasswordEncoder;
use Auth\domain\AccountRepository;
use Auth\application\port\PlayerResolver;
use Auth\application\session\AuthSession;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\twofactor\BackupCodeSet;
use Auth\domain\twofactor\Base32;
use Auth\domain\twofactor\Totp;
use Auth\domain\twofactor\TotpSecret;
use pocketmine\api\entity\Player;

/**
 * Everything two-factor: the login-step code entry, enrollment
 * (enable/confirm) and removal (disable).
 */
final class TwoFactorFlow {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly AuthConfig $cfg,
		private readonly AccountRepository $accounts,
		private readonly PasswordEncoder $encoder,
		private readonly Responder $responder,
		private readonly PlayerResolver $resolver,
		private readonly CompletionFlow $completion,
	) {}

	/**
	 * Entry point for "/2fa <args>". Dispatches subcommands; a bare command
	 * gives state-appropriate guidance instead of silence.
	 */
	public function handleCommand(Player $player, array $args): bool {
		if (!$this->cfg->totpEnabledFeature()) {
			$this->responder->key($player, 'twofa-disabled-feature');
			return true;
		}
		switch (strtolower((string)($args[0] ?? ''))) {
			case 'enable': return $this->enable($player);
			case 'confirm': return $this->confirm($player, (string)($args[1] ?? ''));
			case 'disable': return $this->disable($player, (string)($args[1] ?? ''));
			default: return $this->submitCode($player, trim((string)($args[0] ?? '')));
		}
	}

	// ---- login step ------------------------------------------------------

	private function submitCode(Player $player, string $code): bool {
		$session = $this->sessions->get($player->getId());
		if ($session === null) {
			return false;
		}
		if ($code === '') {
			$this->guide($session, $player);
			return true;
		}
		if ($session->isAwaitingTwoFactor()) {
			$this->gradeLoginStep($session, $player, $code);
			return true;
		}
		if ($session->pendingTotpSecret !== null) {
			return $this->confirm($player, $code); // confirming an enrollment
		}
		$this->responder->key($player, 'twofa-usage');
		return true;
	}

	private function guide(AuthSession $session, Player $player): void {
		if ($session->isAwaitingTwoFactor()) {
			$this->responder->key($player, 'twofa-prompt');
			$account = $session->account;
			if ($account !== null && $account->backupCodeHashes !== null && $account->backupCodeHashes !== []) {
				$this->responder->key($player, 'twofa-login-backup-hint');
			}
			return;
		}
		if ($session->pendingTotpSecret !== null) {
			$this->responder->key($player, 'twofa-confirm-usage');
			return;
		}
		$this->responder->key($player, 'twofa-usage');
	}

	private function gradeLoginStep(AuthSession $session, Player $player, string $code): void {
		$account = $session->account;
		if ($account === null) {
			return;
		}
		$normalized = preg_replace('/\s+/', '', $code) ?? '';

		// TOTP with clock-skew tolerance first...
		if (Totp::matches(
			Base32::decode($account->totpSecret ?? ''),
			$normalized,
			time(),
			$this->cfg->totpPeriod(),
			$this->cfg->totpDigits(),
			$this->cfg->totpWindow(),
		)) {
			$this->completion->complete($session);
			return;
		}

		// ...then single-use backup codes.
		$set = BackupCodeSet::fromHashes($account->backupCodeHashes ?? []);
		$index = $set->match($normalized);
		if ($index === null) {
			$this->responder->key($player, 'twofa-bad');
			return;
		}
		$remaining = $set->burn($index);
		$this->accounts->updateTwoFactor(
			$session->name,
			$account->totpSecret,
			true,
			$remaining->hashes(),
			fn() => null,
		);
		$session->account = $account->withTwoFactor($account->totpSecret, true, $remaining->hashes());
		$this->responder->key($player, 'twofa-backup-used');
		$this->completion->complete($session);
	}

	// ---- enrollment ------------------------------------------------------

	/** Generates a fresh secret and walks the player through enrollment. */
	public function beginEnrollment(AuthSession $session): void {
		$secret = TotpSecret::generate();
		$session->pendingTotpSecret = $secret->base32;
		$player = $this->resolver->byEntityId($session->entityId);
		if ($player === null) {
			return;
		}
		$this->responder->key($player, 'twofa-enable-header');
		$this->responder->key($player, 'twofa-secret-line', ['{secret}' => $secret->grouped()]);
		$this->responder->key($player, 'twofa-uri-line');
		$this->responder->key($player, 'twofa-uri-value', [
			'{uri}' => $secret->otpauthUri($session->name, $this->cfg->totpIssuer(), $this->cfg->totpDigits(), $this->cfg->totpPeriod()),
		]);
		$this->responder->key($player, 'twofa-manual-hint');
		$this->responder->key($player, 'twofa-confirm-usage');
	}

	private function enable(Player $player): bool {
		$session = $this->sessions->get($player->getId());
		if ($session === null) {
			return false;
		}
		if (!$session->hasAccount()) {
			$this->responder->key($player, 'login-notregistered');
			return true;
		}
		if ($session->account?->totpEnabled) {
			$this->responder->key($player, 'twofa-already-enabled');
			return true;
		}
		$this->beginEnrollment($session);
		return true;
	}

	private function confirm(Player $player, string $code): bool {
		$session = $this->sessions->get($player->getId());
		if ($session === null) {
			return false;
		}
		if ($session->pendingTotpSecret === null) {
			$this->responder->key($player, 'twofa-confirm-usage');
			return true;
		}
		$normalized = preg_replace('/\s+/', '', $code) ?? '';
		if (!Totp::matches(
			Base32::decode($session->pendingTotpSecret),
			$normalized,
			time(),
			$this->cfg->totpPeriod(),
			$this->cfg->totpDigits(),
			$this->cfg->totpWindow(),
		)) {
			$this->responder->key($player, 'twofa-bad');
			return true;
		}

		[$set, $codes] = BackupCodeSet::issue($this->cfg->backupCodeCount());
		$base32 = $session->pendingTotpSecret;

		$this->accounts->updateTwoFactor($session->name, $base32, true, $set->hashes(), function () use ($session, $player): void {
			if ($this->sessions->get($session->entityId) !== null) {
				$this->responder->key($this->resolver->byEntityId($session->entityId), 'twofa-confirm-ok');
			}
		});

		// Refresh the local snapshot so the TOTP step applies on next login.
		$session->account = $session->account?->withTwoFactor($base32, true, $set->hashes());
		$session->pendingTotpSecret = null;
		$session->pendingBackupCodes = $codes;

		foreach ($codes as $one) {
			$this->responder->key($player, 'twofa-backup-code', ['{code}' => $one]);
		}
		return true;
	}

	private function disable(Player $player, string $password): bool {
		$session = $this->sessions->get($player->getId());
		if ($session === null) {
			return false;
		}
		$account = $session->account;
		if (!$session->hasAccount()) {
			$this->responder->key($player, 'twofa-not-enrolled');
			return true;
		}
		if ($password === '') {
			$this->responder->key($player, 'twofa-disable-usage');
			return true;
		}
		$this->encoder->verify($password, $account->passwordHash, function (bool $ok) use ($session): void {
			if ($this->sessions->get($session->entityId) === null) {
				return;
			}
			if (!$ok) {
				$this->responder->key($this->resolver->byEntityId($session->entityId), 'twofa-disable-wrongpw');
				return;
			}
			$this->accounts->updateTwoFactor($session->name, null, false, null, fn() => null);
			$session->account = $session->account?->withTwoFactor(null, false, null);
			$this->responder->key($this->resolver->byEntityId($session->entityId), 'twofa-disable-ok');
		});
		return true;
	}
}
