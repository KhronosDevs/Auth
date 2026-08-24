<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\application\port\PlayerResolver;
use Auth\application\ratelimit\RateLimiter;
use Auth\application\session\AuthSession;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\Account;
use Auth\domain\AccountRepository;
use Auth\domain\AuthStage;
use pocketmine\api\scheduler\Scheduler;
use pocketmine\api\entity\Player;
use pocketmine\api\event\PlayerJoinEvent;

/**
 * Connection lifecycle: session creation on join (with timeout arming and
 * the async account lookup) and cleanup on quit. Decides which stage a
 * joining player enters: trusted-IP auto-login, 2FA step, captcha, or
 * password prompt.
 */
final class JoinFlow {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly AuthConfig $cfg,
		private readonly AccountRepository $accounts,
		private readonly CaptchaFlow $captchaFlow,
		private readonly CompletionFlow $completion,
		private readonly Responder $responder,
		private readonly PlayerResolver $resolver,
		private readonly Scheduler $scheduler,
	) {}

	public function handleJoin(PlayerJoinEvent $event): void {
		if (!$this->cfg->enabled()) {
			return;
		}
		$player = $event->getPlayer();
		$session = $this->sessions->create(
			$player->getId(),
			$player->getName(),
			$player->getUniqueId(),
			$player->getAddress(),
			new \pocketmine\port\driven\PlayerRef($player->getUniqueId(), $player->getId(), $player->getName()),
		);

		$this->armTimeout($session);
		$this->responder->dbg(sprintf(
			'handleJoin name=%s eid=%d ip=%s - dispatching load',
			$session->name, $session->entityId, $session->ip,
		));

		$this->accounts->loadByName($session->name, function (?Account $account) use ($session): void {
			$this->responder->dbg(sprintf(
				'load complete name=%s eid=%d found=%s',
				$session->name, $session->entityId, var_export($account !== null, true),
			));
			$this->onLoaded($session, $account);
		});
	}

	public function handleQuit(int $entityId): void {
		$this->sessions->remove($entityId); // idempotent; cancels the timeout task
	}

	private function armTimeout(AuthSession $session): void {
		$seconds = $this->cfg->loginTimeoutSeconds();
		if ($seconds <= 0) {
			return;
		}
		$message = $this->cfg->msg('login-timeout-kick', ['{seconds}' => (string)$seconds]);
		$session->timeoutHandler = $this->scheduler->scheduleDelayedTask(
			function () use ($session, $message, $seconds): void {
				// Guard on our own session tracking; isOnline() alone cannot
				// distinguish "authed meanwhile" from "still frozen".
				if (!$this->sessions->isRestricted($session->entityId)) {
					return;
				}
				$current = $this->resolver->byEntityId($session->entityId);
				if ($current !== null) {
					$this->responder->key($current, 'login-timeout-kick', ['{seconds}' => (string)$seconds]);
					$current->kick($this->responder->colorize($message));
				}
			},
			max(1, $seconds * 20),
		);
	}

	private function onLoaded(AuthSession $session, ?Account $account): void {
		$this->responder->dbg(sprintf('onLoaded name=%s eid=%d stage=%s', $session->name, $session->entityId, $session->stage->name));
		if ($this->sessions->get($session->entityId) === null || $session->stage !== AuthStage::Loading) {
			$this->responder->dbg('onLoaded ABORTED: session gone or not in loading stage');
			return; // quit mid-load
		}
		if ($account === null) {
			$session->stage = AuthStage::Password;
			$this->responder->key($this->resolver->byEntityId($session->entityId), 'join-new');
			return;
		}
		$session->account = $account;

		// Trusted-IP auto-login: skip password (2FA still enforced unless waived).
		if ($this->autoLoginApplies($session, $account)) {
			$this->responder->key($this->resolver->byEntityId($session->entityId), 'login-auto');
			$this->completion->complete($session, announce: false);
			return;
		}
		// Trusted IP but 2FA enforced: jump straight to the code step.
		if (
			$this->cfg->autoLoginEnabled()
			&& $account->hasValidTrustFor($session->ip, time())
			&& $account->requiresTotpNow($this->cfg->totpEnabledFeature(), $this->cfg->totpRequired())
			&& $this->cfg->totpRequireWithTrustedIp()
		) {
			$session->stage = AuthStage::TwoFactor;
			$this->responder->key($this->resolver->byEntityId($session->entityId), 'twofa-prompt');
			return;
		}

		if ($this->captchaFlow->isDue($session)) {
			$this->captchaFlow->issue($session);
			return;
		}
		$session->stage = AuthStage::Password;
		$this->responder->key($this->resolver->byEntityId($session->entityId), 'join-registered');
	}

	private function autoLoginApplies(AuthSession $session, Account $account): bool {
		return $this->cfg->autoLoginEnabled()
			&& $account->hasValidTrustFor($session->ip, time())
			&& (
				!$account->requiresTotpNow($this->cfg->totpEnabledFeature(), $this->cfg->totpRequired())
				|| !$this->cfg->totpRequireWithTrustedIp()
			);
	}
}
