<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\application\port\PasswordEncoder;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\Account;
use Auth\domain\AccountRepository;
use Auth\domain\twofactor\BackupCodeSet;
use pocketmine\api\command\CommandSender;

/**
 * Administrative account management: force-unregister, password reset and
 * backup-code regeneration. Works on offline accounts (storage-level);
 * online targets are kicked so their session state cannot desync.
 */
final class AdministrationFlow {
	/** @var ?\Closure(string): ?\pocketmine\api\entity\Player wired by the facade */
	private ?\Closure $onlineLookup = null;

	public function __construct(
		private readonly AuthConfig $cfg,
		private readonly AccountRepository $accounts,
		private readonly PasswordEncoder $encoder,
		private readonly Responder $responder,
	) {}

	public function setOnlineLookup(\Closure $lookup): void {
		$this->onlineLookup = $lookup;
	}

	public function unregister(CommandSender $admin, string $target): void {
		$this->accounts->delete($target, function (bool $existed) use ($admin, $target): void {
			$this->responder->key($admin, 'admin-unregistered', ['{player}' => $target]);
			if (!$existed) {
				$this->responder->raw($admin, '&7(no stored account matched)');
			}
		});
		$this->kickOnline($target, 'Your account was unregistered by an admin.');
	}

	public function resetPassword(CommandSender $admin, string $target, string $newPassword): void {
		if (strlen($newPassword) < $this->cfg->minPasswordLength()) {
			$this->responder->key($admin, 'changepw-short', ['{min}' => (string)$this->cfg->minPasswordLength()]);
			return;
		}
		$this->encoder->hash($newPassword, function (string $hash) use ($admin, $target): void {
			$this->accounts->updatePasswordHash($target, $hash, fn() => $this->responder->key(
				$admin,
				'admin-resetpw',
				['{player}' => $target],
			));
		});
		$this->kickOnline($target, 'Your password was reset by an admin.');
	}

	public function regenerateBackupCodes(CommandSender $admin, string $target): void {
		$this->accounts->loadByName($target, function (?Account $account) use ($admin, $target): void {
			if ($account === null) {
				$this->responder->key($admin, 'login-notregistered');
				return;
			}
			if (!$account->totpEnabled) {
				$this->responder->key($admin, 'twofa-not-enrolled');
				return;
			}
			[$set, $codes] = BackupCodeSet::issue($this->cfg->backupCodeCount());
			$this->accounts->updateTwoFactor($target, $account->totpSecret, true, $set->hashes(), function () use ($admin, $target, $codes): void {
				$this->responder->key($admin, 'admin-codes-header', ['{player}' => $target]);
				foreach ($codes as $code) {
					$this->responder->key($admin, 'twofa-backup-code', ['{code}' => $code]);
				}
			});
		});
	}

	private function kickOnline(string $name, string $reason): void {
		$online = $this->onlineLookup !== null ? ($this->onlineLookup)($name) : null;
		$online?->kick($reason);
	}
}
