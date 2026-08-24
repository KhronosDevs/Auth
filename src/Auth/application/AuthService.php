<?php

declare(strict_types=1);

namespace Auth\application;

use Auth\application\flow\AdministrationFlow;
use Auth\application\flow\CaptchaFlow;
use Auth\application\flow\CompletionFlow;
use Auth\application\flow\JoinFlow;
use Auth\application\flow\LoginFlow;
use Auth\application\flow\PasswordChangeFlow;
use Auth\application\flow\RegistrationFlow;
use Auth\application\flow\TwoFactorFlow;
use Auth\application\ratelimit\RateLimiter;
use Auth\application\session\SessionManager;
use Auth\config\AuthConfig;
use pocketmine\api\command\CommandSender;
use pocketmine\api\entity\Player;
use pocketmine\api\event\PlayerJoinEvent;

/**
 * The application facade: the single entry point commands and listeners
 * talk to. Contains no business logic of its own - every use case lives in
 * a dedicated flow class; this type only routes to them.
 */
final class AuthService {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly AuthConfig $cfg,
		private readonly RateLimiter $limiter,
		private readonly JoinFlow $joinFlow,
		private readonly RegistrationFlow $registration,
		private readonly LoginFlow $login,
		private readonly CaptchaFlow $captcha,
		private readonly TwoFactorFlow $twoFactor,
		private readonly PasswordChangeFlow $passwordChange,
		private readonly AdministrationFlow $administration,
	) {}

	public function sessions(): SessionManager {
		return $this->sessions;
	}

	public function limiter(): RateLimiter {
		return $this->limiter;
	}

	// ---- lifecycle -------------------------------------------------------

	public function handleJoin(PlayerJoinEvent $event): void {
		$this->joinFlow->handleJoin($event);
	}

	public function handleQuit(int $entityId): void {
		$this->joinFlow->handleQuit($entityId);
	}

	// ---- commands ---------------------------------------------------------

	public function handleRegisterCommand(Player $player, array $args): bool {
		return $this->registration->handleCommand($player, $args);
	}

	public function handleLoginCommand(Player $player, array $args): bool {
		return $this->login->handleCommand($player, $args);
	}

	public function handleCaptchaCommand(Player $player, array $args): bool {
		return $this->captcha->handleCommand($player, $args);
	}

	public function handleTwoFaCommand(Player $player, array $args): bool {
		return $this->twoFactor->handleCommand($player, $args);
	}

	public function handleChangePasswordCommand(Player $player, array $args): bool {
		return $this->passwordChange->handleCommand($player, $args);
	}

	// ---- administration ----------------------------------------------------

	public function adminUnregister(CommandSender $admin, string $target): void {
		$this->administration->unregister($admin, $target);
	}

	public function adminResetPassword(CommandSender $admin, string $target, string $newPassword): void {
		$this->administration->resetPassword($admin, $target, $newPassword);
	}

	public function adminRegenBackupCodes(CommandSender $admin, string $target): void {
		$this->administration->regenerateBackupCodes($admin, $target);
	}

	// ---- maintenance --------------------------------------------------------

	public function periodicPrune(): void {
		$this->limiter->prune($this->cfg->rlDecayMinutes() * 60);
	}
}
