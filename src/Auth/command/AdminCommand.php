<?php

declare(strict_types=1);

namespace Auth\command;

use Auth\application\AuthService;
use pocketmine\api\command\Command;
use pocketmine\api\command\CommandSender;

/**
 * /authadmin unregister <player>
 * /authadmin resetpw <player> <newPassword>
 * /authadmin codes <player>       - regenerate single-use backup codes
 *
 * Works on offline accounts (storage-level); online targets are kicked so
 * their in-memory session state cannot desync from the store.
 */
final class AdminCommand extends Command {
	private const USAGE =
		'Usage: /authadmin unregister <player> | resetpw <player> <newPassword> | codes <player>';

	public function __construct(private readonly AuthService $auth) {
		parent::__construct(
			name: 'authadmin',
			description: 'Manage Auth accounts (unregister, password reset, backup codes)',
			usage: self::USAGE,
			aliases: ['authop'],
			permission: 'auth.admin',
		);
	}

	public function execute(CommandSender $sender, array $args): bool {
		if (!$sender->hasPermission('auth.admin')) {
			$sender->sendMessage('You do not have permission.');
			return true;
		}
		switch (strtolower((string)($args[0] ?? ''))) {
			case 'unregister':
				if (!isset($args[1])) {
					break;
				}
				$this->auth->adminUnregister($sender, (string)$args[1]);
				return true;
			case 'resetpw':
			case 'resetpassword':
				if (!isset($args[2])) {
					break;
				}
				$this->auth->adminResetPassword($sender, (string)$args[1], (string)$args[2]);
				return true;
			case 'codes':
			case 'regencodes':
				if (!isset($args[1])) {
					break;
				}
				$this->auth->adminRegenBackupCodes($sender, (string)$args[1]);
				return true;
		}
		$sender->sendMessage(self::USAGE);
		return true;
	}
}
