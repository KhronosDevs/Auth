<?php

declare(strict_types=1);

namespace Auth\command;

use Auth\application\AuthService;
use pocketmine\api\command\Command;
use pocketmine\api\command\CommandSender;

/** /changepassword <oldPassword> <newPassword> (requires authentication) */
final class ChangePasswordCommand extends Command {
	public function __construct(private readonly AuthService $auth) {
		parent::__construct(
			name: 'changepassword',
			description: 'Change your account password',
			usage: '/changepassword <oldPassword> <newPassword>',
			aliases: ['changepw'],
		);
	}

	public function execute(CommandSender $sender, array $args): bool {
		$player = $sender->getPlayer();
		if ($player === null) {
			$sender->sendMessage('This command can only be used in-game.');
			return true;
		}
		return $this->auth->handleChangePasswordCommand($player, $args);
	}
}
