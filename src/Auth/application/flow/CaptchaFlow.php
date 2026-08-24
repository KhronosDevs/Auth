<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\application\captcha\CaptchaService;
use Auth\application\port\PlayerResolver;
use Auth\application\session\AuthSession;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\AuthStage;
use pocketmine\api\entity\Player;

/**
 * The captcha stage: deciding when a challenge is due, issuing challenges
 * into the session, and grading answers.
 */
final class CaptchaFlow {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly CaptchaService $captcha,
		private readonly AuthConfig $cfg,
		private readonly Responder $responder,
		private readonly PlayerResolver $resolver,
	) {}

	public function isDue(AuthSession $session): bool {
		if (!$this->captcha->isEnabled()) {
			return false;
		}
		return $this->captcha->isDueFor($session->failedLogins, $this->cfg->captchaTriggerAfterFailures());
	}

	/** Install a fresh challenge and move the session to the captcha stage. */
	public function issue(AuthSession $session): void {
		$challenge = $this->captcha->generate();
		$session->captchaAnswer = $challenge->answer;
		$session->captchaQuestion = $challenge->question;
		$session->captchaExpiresAt = time() + $this->cfg->captchaExpiresSeconds();
		$session->captchaAttempts = 0;
		$session->stage = AuthStage::Captcha;

		$key = $this->cfg->captchaStyle() === CaptchaService::STYLE_MATH ? 'captcha-math' : 'captcha-text';
		$this->responder->key($this->resolver->byEntityId($session->entityId), $key, ['{code}' => $challenge->question]);
	}

	/** /captcha <code>. Returns true when the input was handled. */
	public function handleCommand(Player $player, array $args): bool {
		$session = $this->sessions->get($player->getId());
		if ($session === null) {
			return false;
		}
		if (!isset($args[0])) {
			$this->responder->key($player, 'captcha-usage');
			return true;
		}
		if (!$this->captcha->isEnabled() || $session->stage !== AuthStage::Captcha) {
			$this->responder->key($player, 'captcha-not-required');
			return true;
		}
		if (time() > $session->captchaExpiresAt) {
			$this->issue($session);
			$this->responder->key($player, 'captcha-expired');
			return true;
		}
		if (!hash_equals($session->captchaAnswer, strtoupper(trim((string)$args[0])))) {
			$session->captchaAttempts++;
			if ($session->captchaAttempts >= $this->cfg->captchaMaxAttempts()) {
				// Regenerate - brute-forcing one challenge is futile.
				$this->issue($session);
			} else {
				$this->responder->key($player, 'captcha-bad');
			}
			return true;
		}
		// Solved: advance to the password stage.
		$session->captchaAnswer = '';
		$session->stage = AuthStage::Password;
		$this->responder->key($player, $session->hasAccount() ? 'join-registered' : 'join-new');
		return true;
	}
}
