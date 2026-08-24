<?php

declare(strict_types=1);

namespace Auth\application\session;

use Auth\domain\Account;
use Auth\domain\AuthStage;
use pocketmine\api\scheduler\TaskHandler;
use pocketmine\port\driven\PlayerRef;

/**
 * Per-connection authentication state. Plain public fields: this object is
 * touched on every gated event and must not pay accessor overhead.
 *
 * HOT-PATH CONTRACT (see SessionManager): restriction checks are an isset()
 * against an int-keyed map - nothing in this class runs per tick.
 */
final class AuthSession {
	/** base32 pending secret while enrolling via /2fa enable */
	public ?string $pendingTotpSecret = null;
	/** plaintext backup codes shown exactly once during enrollment confirmation */
	public ?array $pendingBackupCodes = null;
	/** expected captcha answer ('' when no challenge active) */
	public string $captchaAnswer = '';
	/** captcha text shown to the player ("5 + 7" or "XJ4K9") */
	public string $captchaQuestion = '';
	public int $captchaExpiresAt = 0;
	public int $captchaAttempts = 0;
	/** failed login attempts this session */
	public int $failedLogins = 0;
	/** true while a hash/verify/DB job for this session is in flight */
	public bool $busy = false;
	/** account snapshot once loaded (null = unregistered); withered on change */
	public ?Account $account = null;
	/** delayed-task handler that kicks on login timeout */
	public ?TaskHandler $timeoutHandler = null;

	public function __construct(
		public readonly int $entityId,
		public readonly string $name,
		public readonly string $uuid,
		public readonly string $ip,
		public readonly PlayerRef $ref,
		public AuthStage $stage = AuthStage::Loading,
	) {}

	public function isAwaitingTwoFactor(): bool {
		return $this->stage === AuthStage::TwoFactor;
	}

	public function hasAccount(): bool {
		return $this->account !== null;
	}
}
