<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\application\port\PasswordEncoder;
use Auth\application\port\PlayerResolver;
use Auth\application\ratelimit\RateLimiter;
use Auth\application\session\AuthSession;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\AuthStage;
use pocketmine\api\entity\Player;

/**
 * Password authentication: /login <password>.
 * Verifies off-thread, counts failures (kick + captcha escalation), and on
 * success either advances to the 2FA stage or completes the login.
 */
final class LoginFlow {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly RateLimiter $limiter,
		private readonly AuthConfig $cfg,
		private readonly PasswordEncoder $encoder,
		private readonly Responder $responder,
		private readonly PlayerResolver $resolver,
		private readonly CompletionFlow $completion,
		private readonly CaptchaFlow $captchaFlow,
	) {}

	/** Returns true when the input was handled. */
	public function handleCommand(Player $player, array $args): bool {
		if (!$this->cfg->enabled()) {
			return false;
		}
		$session = $this->sessions->get($player->getId());
		if ($session === null || $session->stage === AuthStage::Authenticated) {
			return false;
		}
		if (!isset($args[0])) {
			$this->responder->key($player, 'login-usage');
			return true;
		}
		$account = $session->account;
		if (!$session->hasAccount()) {
			$this->responder->key($player, 'login-notregistered');
			return true;
		}
		if ($session->busy || $session->stage === AuthStage::Loading) {
			return true;
		}
		if ($session->stage === AuthStage::Captcha) {
			$this->captchaFlow->issue($session);
			return true;
		}
		[$allowed, $retryAfter] = $this->limiter->check($session->ip, $session->name);
		if (!$allowed) {
			$this->responder->key($player, 'rate-limited', ['{seconds}' => (string)$retryAfter]);
			return true;
		}

		$password = (string)$args[0];
		$hash = $account->passwordHash;
		$session->busy = true;
		$this->encoder->verify($password, $hash, function (bool $ok) use ($session): void {
			$session->busy = false;
			if ($this->sessions->get($session->entityId) === null) {
				return;
			}
			if (!$ok) {
				$this->reject($session);
				return;
			}
			$this->accept($session);
		});
		return true;
	}

	private function reject(AuthSession $session): void {
		$session->failedLogins++;
		$this->limiter->failure($session->ip, $session->name);

		$maxAttempts = $this->cfg->maxLoginAttempts();
		if ($session->failedLogins >= $maxAttempts) {
			$this->resolver->byEntityId($session->entityId)?->kick(
				$this->responder->colorize($this->cfg->msg('login-kick-attempts')),
			);
			return;
		}
		if ($this->captchaFlow->isDue($session)) {
			$this->captchaFlow->issue($session);
			return;
		}
		$remaining = max(1, $maxAttempts - $session->failedLogins);
		$this->responder->key(
			$this->resolver->byEntityId($session->entityId),
			'login-wrong',
			['{attempts}' => (string)$remaining],
		);
	}

	private function accept(AuthSession $session): void {
		$account = $session->account;
		if ($account === null) {
			return;
		}
		if ($account->requiresTotpNow($this->cfg->totpEnabledFeature(), $this->cfg->totpRequired())) {
			$session->stage = AuthStage::TwoFactor;
			$player = $this->resolver->byEntityId($session->entityId);
			$this->responder->key($player, 'twofa-prompt');
			if ($account->backupCodeHashes !== null && $account->backupCodeHashes !== []) {
				$this->responder->key($player, 'twofa-login-backup-hint');
			}
			return;
		}
		$this->completion->complete($session);
	}
}
