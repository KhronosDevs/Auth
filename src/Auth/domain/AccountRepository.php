<?php

declare(strict_types=1);

namespace Auth\domain;

/**
 * Persistence port for accounts (hexagonal architecture - the domain owns
 * the interface, infrastructure implements it).
 *
 * All operations are ASYNCHRONOUS by contract: results are delivered through
 * the given callbacks, which implementations MUST invoke on the main thread.
 * Callers never block on storage. This shape is what allows the SQLite
 * backend to serialize every query onto a single worker without leaking
 * threading concerns into flows.
 */
interface AccountRepository {
	/** @param callable(?Account): void $onLoaded null = not found */
	public function loadByName(string $name, callable $onLoaded): void;

	/** @param callable(bool): void $onDone false = name already taken */
	public function add(Account $account, callable $onDone): void;

	public function updatePasswordHash(string $name, string $passwordHash, callable $onDone): void;

	/** Full 2FA state write: secret, enabled flag and backup-code hashes. */
	public function updateTwoFactor(string $name, ?string $base32Secret, bool $enabled, ?array $backupCodeHashes, callable $onDone): void;

	public function recordLogin(string $name, string $ip, int $trustedUntil, callable $onDone): void;

	/** @param callable(bool): void $onDone true = a row was deleted */
	public function delete(string $name, callable $onDone): void;
}
