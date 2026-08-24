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
use Auth\domain\Account;
use Auth\domain\AccountRepository;
use Auth\domain\AuthStage;
use pocketmine\api\entity\Player;

/**
 * Account creation: /register <password> <confirmPassword>.
 * Validates input, hashes off-thread, persists via the repository, then
 * hands the player straight into the authenticated state.
 */
final class RegistrationFlow {
	private ?TwoFactorFlow $twoFactor = null;

	public function __construct(
		private readonly SessionManager $sessions,
		private readonly RateLimiter $limiter,
		private readonly AuthConfig $cfg,
		private readonly PasswordEncoder $encoder,
		private readonly AccountRepository $accounts,
		private readonly Responder $responder,
		private readonly PlayerResolver $resolver,
		private readonly CompletionFlow $completion,
		private readonly CaptchaFlow $captchaFlow,
	) {}

	/** Wired by the facade after construction (TwoFactorFlow depends on CompletionFlow). */
	public function setTwoFactor(TwoFactorFlow $twoFactor): void {
		$this->twoFactor = $twoFactor;
	}

	/** Returns true when the input was handled. */
	public function handleCommand(Player $player, array $args): bool {
		if (!$this->cfg->enabled()) {
			return false;
		}
		$session = $this->sessions->get($player->getId());
		if ($session === null || $session->stage === AuthStage::Authenticated) {
			return false; // not ours (already authed -> unknown command)
		}
		if (count($args) < 2) {
			$this->responder->key($player, 'register-usage');
			return true;
		}
		if ($session->busy || $session->stage === AuthStage::Loading) {
			return true; // work in flight or account row still loading
		}
		if ($session->stage === AuthStage::Captcha) {
			$this->captchaFlow->issue($session);
			return true;
		}
		if ($session->hasAccount()) {
			$this->responder->key($player, 'register-exists');
			return true;
		}

		[$password, $confirm] = [(string)$args[0], (string)$args[1]];
		if ($password !== $confirm) {
			$this->responder->key($player, 'register-mismatch');
			return true;
		}
		if (strlen($password) < $this->cfg->minPasswordLength()) {
			$this->responder->key($player, 'register-short', ['{min}' => (string)$this->cfg->minPasswordLength()]);
			return true;
		}
		[$allowed, $retryAfter] = $this->limiter->check($session->ip, $session->name);
		if (!$allowed) {
			$this->responder->key($player, 'rate-limited', ['{seconds}' => (string)$retryAfter]);
			return true;
		}

		$session->busy = true;
		$this->encoder->hash($password, function (string $hash) use ($session): void {
			$session->busy = false;
			if ($this->sessions->get($session->entityId) === null) {
				return; // quit mid-register
			}
			$account = Account::register($session->name, $hash, $session->ip, time());
			$this->accounts->add($account, function (bool $added) use ($session, $account): void {
				if ($this->sessions->get($session->entityId) === null) {
					return;
				}
				if (!$added) {
					$this->responder->key($this->resolver->byEntityId($session->entityId), 'register-exists');
					return;
				}
				// Seed the snapshot NOW: /2fa enable, /2fa disable and
				// /changepassword gate on it - without this they would
				// report "no account" until relog.
				$session->account = $account;
				$this->responder->key($this->resolver->byEntityId($session->entityId), 'register-ok');
				$this->completion->complete($session, announce: false);
				if ($this->cfg->totpEnabledFeature() && $this->cfg->totpOnRegister()) {
					$this->twoFactor?->beginEnrollment($session);
				}
			});
		});
		return true;
	}
}
