<?php

declare(strict_types=1);

namespace Auth\command;

use Auth\application\AuthService;
use pocketmine\api\command\Command;
use pocketmine\api\command\CommandSender;

/** /register <password> <confirmPassword> */
final class RegisterCommand extends Command {
	public function __construct(private readonly AuthService $auth) {
		parent::__construct(
			name: 'register',
			description: 'Create an account',
			usage: '/register <password> <confirmPassword>',
		);
	}

	public function execute(CommandSender $sender, array $args): bool {
		$player = $sender->getPlayer();
		if ($player === null) {
			$sender->sendMessage('This command can only be used in-game.');
			return true;
		}
		return $this->auth->handleRegisterCommand($player, $args);
	}
}
