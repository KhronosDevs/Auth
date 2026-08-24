<?php

declare(strict_types=1);

namespace Auth\infrastructure\storage\sqlite;

/**
 * SQLite account store - worker-thread side.
 *
 * CRITICAL DESIGN CONSTRAINT: SQLite permits only one reader/writer at a
 * time. Every query in the whole plugin funnels through JobQueue, which
 * keeps AT MOST ONE DbTask in flight on the shared pool at any moment.
 * From SQLite's point of view all access is therefore strictly sequential
 * single-threaded: no concurrent connections, no SQLITE_BUSY contention.
 * Each job opens its own short-lived PDO connection (sub-millisecond) and
 * closes it; WAL mode + busy_timeout are set defensively anyway.
 *
 * This class is loaded on the main thread BEFORE any submission (see
 * Main::onEnable) so pmmpthread workers can call into it. It must stay
 * dependency-free: PDO + json only, no plugin service objects.
 */
final class SqliteExecutor {
	public const OP_LOAD = 'load';
	public const OP_ADD = 'register';
	public const OP_SET_HASH = 'set_hash';
	public const OP_SET_TOTP = 'set_totp';
	public const OP_RECORD_LOGIN = 'record_login';
	public const OP_DELETE = 'delete';

	/**
	 * Execute one operation. $request carries 'op', 'path' and scalar
	 * params; the response is a plain scalar-keyed array.
	 *
	 * @param array<string, mixed> $request
	 * @return array<string, mixed>
	 */
	/** @var array<string, \PDO> per-THREAD connection cache (each pmmpthread
	 *  has its own VM, so this static is thread-local by construction).
	 *  Because JobQueue pins every DB task to ONE worker, exactly one entry
	 *  exists in practice: a single warm connection for the whole plugin. */
	private static array $connections = [];

	public static function execute(array $request): array {
		$path = (string)$request['path'];
		$pdo = self::$connections[$path] ?? null;
		if ($pdo === null) {
			$pdo = self::connect($path);
			self::$connections[$path] = $pdo;
		}
		return self::dispatch($pdo, (string)($request['op'] ?? ''), $request);
	}

	private static function connect(string $path): \PDO {
		$pdo = new \PDO('sqlite:' . $path, null, null, [
			\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
			\PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
		]);
		self::ensureSchema($pdo);
		return $pdo;
	}

	private static function dispatch(\PDO $pdo, string $op, array $r): array {
		switch ($op) {
			case self::OP_LOAD:
				$stmt = $pdo->prepare('SELECT * FROM accounts WHERE name = :name COLLATE NOCASE LIMIT 1');
				$stmt->execute(['name' => (string)$r['name']]);
				$row = $stmt->fetch();
				return ['found' => $row !== false, 'account' => $row === false ? null : self::serializeRow($row)];

			case self::OP_ADD:
				$stmt = $pdo->prepare(
					'INSERT OR IGNORE INTO accounts
					 (name, password_hash, totp_secret, totp_enabled, backup_codes,
					  register_ip, register_time, last_login_time, last_login_ip, trusted_ip, trusted_until)
					 VALUES (:name, :hash, NULL, 0, NULL, :ip, :time, 0, \'\', NULL, 0)'
				);
				$stmt->execute([
					'name' => (string)$r['name'],
					'hash' => (string)$r['hash'],
					'ip' => (string)$r['ip'],
					'time' => (int)$r['time'],
				]);
				return ['ok' => $stmt->rowCount() > 0];

			case self::OP_SET_HASH:
				$stmt = $pdo->prepare('UPDATE accounts SET password_hash = :hash WHERE name = :name COLLATE NOCASE');
				$stmt->execute(['hash' => (string)$r['hash'], 'name' => (string)$r['name']]);
				return ['ok' => true];

			case self::OP_SET_TOTP:
				$stmt = $pdo->prepare(
					'UPDATE accounts SET totp_secret = :secret, totp_enabled = :enabled, backup_codes = :codes
					 WHERE name = :name COLLATE NOCASE'
				);
				$stmt->execute([
					'secret' => (string)($r['secret'] ?? ''),
					'enabled' => empty($r['enabled']) ? 0 : 1,
					'codes' => isset($r['codes']) && is_array($r['codes']) ? json_encode(array_values($r['codes'])) : ($r['codes'] ?? null),
					'name' => (string)$r['name'],
				]);
				return ['ok' => true];

			case self::OP_RECORD_LOGIN:
				// Trust window refresh happens on every successful login.
				$stmt = $pdo->prepare(
					'UPDATE accounts
					 SET last_login_time = :time, last_login_ip = :ip,
					     trusted_ip = :ip, trusted_until = :until
					 WHERE name = :name COLLATE NOCASE'
				);
				$stmt->execute([
					'time' => (int)$r['time'],
					'ip' => (string)$r['ip'],
					'until' => (int)$r['trusted_until'],
					'name' => (string)$r['name'],
				]);
				return ['ok' => true];

			case self::OP_DELETE:
				$stmt = $pdo->prepare('DELETE FROM accounts WHERE name = :name COLLATE NOCASE');
				$stmt->execute(['name' => (string)$r['name']]);
				return ['ok' => $stmt->rowCount() > 0];
		}
		throw new \InvalidArgumentException('Unknown DB op: ' . $op);
	}

	private static function ensureSchema(\PDO $pdo): void {
		$pdo->exec('PRAGMA journal_mode=WAL');
		$pdo->exec('PRAGMA synchronous=NORMAL');
		$pdo->exec('PRAGMA busy_timeout=5000');
		$pdo->exec(
			'CREATE TABLE IF NOT EXISTS accounts (
				name TEXT PRIMARY KEY COLLATE NOCASE,
				password_hash TEXT NOT NULL,
				totp_secret TEXT,
				totp_enabled INTEGER NOT NULL DEFAULT 0,
				backup_codes TEXT,
				register_ip TEXT NOT NULL DEFAULT \'\',
				register_time INTEGER NOT NULL DEFAULT 0,
				last_login_time INTEGER NOT NULL DEFAULT 0,
				last_login_ip TEXT NOT NULL DEFAULT \'\',
				trusted_ip TEXT,
				trusted_until INTEGER NOT NULL DEFAULT 0
			)'
		);
	}

	/**
	 * Normalize a fetched row so it survives JSON transport as scalars only.
	 *
	 * @return array<string, mixed>
	 */
	private static function serializeRow(array $row): array {
		return [
			'name' => (string)($row['name'] ?? ''),
			'password_hash' => (string)($row['password_hash'] ?? ''),
			'totp_secret' => isset($row['totp_secret']) && $row['totp_secret'] !== null && $row['totp_secret'] !== '' ? (string)$row['totp_secret'] : null,
			'totp_enabled' => (int)($row['totp_enabled'] ?? 0),
			'backup_codes' => isset($row['backup_codes']) && is_string($row['backup_codes']) ? json_decode($row['backup_codes'], true) : null,
			'register_ip' => (string)($row['register_ip'] ?? ''),
			'register_time' => (int)($row['register_time'] ?? 0),
			'last_login_time' => (int)($row['last_login_time'] ?? 0),
			'last_login_ip' => (string)($row['last_login_ip'] ?? ''),
			'trusted_ip' => isset($row['trusted_ip']) && $row['trusted_ip'] !== null && $row['trusted_ip'] !== '' ? (string)$row['trusted_ip'] : null,
			'trusted_until' => (int)($row['trusted_until'] ?? 0),
		];
	}
}
