<?php

declare(strict_types=1);

namespace Auth\command;

use Auth\application\AuthService;
use pocketmine\api\command\Command;
use pocketmine\api\command\CommandSender;

/**
 * /2fa <code>          - submit a login-step TOTP/backup code
 * /2fa enable          - start enrollment (shows secret + otpauth URI)
 * /2fa confirm <code>  - verify the secret and receive backup codes
 * /2fa disable <pw>    - turn 2FA off (password required)
 */
final class TwoFaCommand extends Command {
	public function __construct(private readonly AuthService $auth) {
		parent::__construct(
			name: '2fa',
			description: 'Two-factor authentication: /2fa <code|enable|confirm|disable>',
			usage: '/2fa <code|enable|confirm <code>|disable <password>>',
		);
	}

	public function execute(CommandSender $sender, array $args): bool {
		$player = $sender->getPlayer();
		if ($player === null) {
			$sender->sendMessage('This command can only be used in-game.');
			return true;
		}
		return $this->auth->handleTwoFaCommand($player, $args);
	}
}
