<?php

declare(strict_types=1);

namespace Auth\infrastructure\storage\sqlite;

use Auth\domain\Account;
use Auth\domain\AccountRepository;
use Auth\infrastructure\async\JobQueue;

/**
 * SQLite implementation of the domain's AccountRepository port.
 *
 * Thin translation layer only: Account <-> scalar request arrays. Every
 * operation is delegated to JobQueue, which guarantees exactly one in-flight
 * DbTask (SQLite single-writer discipline) and main-thread callbacks.
 */
final class SqliteAccountRepository implements AccountRepository {
	public function __construct(
		private readonly JobQueue $queue,
		private readonly string $dbPath,
	) {}

	public function loadByName(string $name, callable $onLoaded): void {
		$this->queue->db(['op' => SqliteExecutor::OP_LOAD, 'path' => $this->dbPath, 'name' => $name],
			static function (array $res) use ($onLoaded): void {
				$row = !empty($res['found']) ? $res['account'] : null;
				$onLoaded(is_array($row) ? Account::fromRow($row) : null);
			});
	}

	public function add(Account $account, callable $onDone): void {
		$this->queue->db([
			'op' => SqliteExecutor::OP_ADD,
			'path' => $this->dbPath,
			'name' => $account->name,
			'hash' => $account->passwordHash,
			'ip' => $account->registerIp,
			'time' => $account->registerTime,
		], static function (array $res) use ($onDone): void {
			$onDone(!empty($res['ok']));
		});
	}

	public function updatePasswordHash(string $name, string $passwordHash, callable $onDone): void {
		$this->queue->db(['op' => SqliteExecutor::OP_SET_HASH, 'path' => $this->dbPath, 'name' => $name, 'hash' => $passwordHash],
			static fn() => $onDone());
	}

	public function updateTwoFactor(string $name, ?string $base32Secret, bool $enabled, ?array $backupCodeHashes, callable $onDone): void {
		$this->queue->db([
			'op' => SqliteExecutor::OP_SET_TOTP,
			'path' => $this->dbPath,
			'name' => $name,
			'secret' => $base32Secret ?? '',
			'enabled' => $enabled ? 1 : 0,
			'codes' => $backupCodeHashes !== null ? array_values($backupCodeHashes) : null,
		], static fn() => $onDone());
	}

	public function recordLogin(string $name, string $ip, int $trustedUntil, callable $onDone): void {
		$this->queue->db([
			'op' => SqliteExecutor::OP_RECORD_LOGIN,
			'path' => $this->dbPath,
			'name' => $name,
			'ip' => $ip,
			'time' => time(),
			'trusted_until' => $trustedUntil,
		], static fn() => $onDone());
	}

	public function delete(string $name, callable $onDone): void {
		$this->queue->db(['op' => SqliteExecutor::OP_DELETE, 'path' => $this->dbPath, 'name' => $name],
			static function (array $res) use ($onDone): void {
				$onDone(!empty($res['ok']));
			});
	}
}
