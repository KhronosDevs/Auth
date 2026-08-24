<?php

declare(strict_types=1);

namespace Auth\command;

use Auth\application\AuthService;
use pocketmine\api\command\Command;
use pocketmine\api\command\CommandSender;

/** /login <password> */
final class LoginCommand extends Command {
	public function __construct(private readonly AuthService $auth) {
		parent::__construct(
			name: 'login',
			description: 'Log in to your account',
			usage: '/login <password>',
			aliases: ['log'],
		);
	}

	public function execute(CommandSender $sender, array $args): bool {
		$player = $sender->getPlayer();
		if ($player === null) {
			$sender->sendMessage('This command can only be used in-game.');
			return true;
		}
		return $this->auth->handleLoginCommand($player, $args);
	}
}
