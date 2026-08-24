<?php

declare(strict_types=1);

namespace Auth\application\port;

/**
 * Async password hashing/verification port. Implementations MUST run the
 * (expensive) hashing on worker threads and deliver results on the main
 * thread - the main thread never hashes.
 */
interface PasswordEncoder {
	/** @param callable(string $hash): void $onDone */
	public function hash(string $password, callable $onDone): void;

	/** @param callable(bool $ok): void $onDone */
	public function verify(string $password, string $hash, callable $onDone): void;
}
