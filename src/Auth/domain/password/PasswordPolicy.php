<?php

declare(strict_types=1);

namespace Auth\domain\password;

/**
 * Immutable hashing parameters resolved from config once at boot and passed
 * around as a single value object on the main thread. The actual hashing
 * runs on worker threads via infrastructure (HashTask), which receives the
 * scalars; this VO owns the resolution policy.
 *
 * Algorithm selection:
 *  - "auto": Argon2id when the PHP build provides it (PASSWORD_ARGON2ID
 *    defined), otherwise bcrypt. The current server build lacks Argon2,
 *    so auto currently resolves to bcrypt and upgrades transparently.
 */
final class PasswordPolicy {
	public const ALGO_AUTO = 'auto';
	public const ALGO_ARGON2ID = 'argon2id';
	public const ALGO_BCRYPT = 'bcrypt';

	public function __construct(
		public readonly string $algorithm,
		public readonly int $bcryptCost,
		public readonly int $argonMemoryKib,
		public readonly int $argonTimeCost,
		public readonly int $argonThreads,
	) {}

	public static function fromConfigValues(string $algo, int $bcryptCost, int $argonMem, int $argonTime, int $argonThreads): self {
		return new self(strtolower($algo), max(4, $bcryptCost), $argonMem, $argonTime, $argonThreads);
	}

	/**
	 * Resolved PHP algo constant + options for password_hash().
	 *
	 * @return array{0: int|string, 1: array<string, mixed>}
	 */
	public function resolve(): array {
		return PasswordHasher::resolve($this->algorithm, $this->bcryptCost, $this->argonMemoryKib, $this->argonTimeCost, $this->argonThreads);
	}

	/** Human-readable active algorithm, e.g. "bcrypt/12". */
	public function describe(): string {
		[$algo] = $this->resolve();
		return $algo === PASSWORD_BCRYPT
			? 'bcrypt/' . max(4, min(31, $this->bcryptCost))
			: 'argon2id';
	}
}
