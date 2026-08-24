<?php

declare(strict_types=1);

namespace Auth\domain\password;

/**
 * Worker-thread-side hashing statics. Pure functions over scalars (task
 * properties must be scalars to cross pmmpthread boundaries), no state.
 */
final class PasswordHasher {
	// Literal strings (not aliased to PasswordPolicy) so this class stays
	// loadable on pmmpthread workers that never saw the policy VO.
	public const ALGO_AUTO = 'auto';
	public const ALGO_ARGON2ID = 'argon2id';
	public const ALGO_BCRYPT = 'bcrypt';

	/**
	 * @return array{0: int|string, 1: array<string, mixed>} algo constant + options
	 */
	public static function resolve(string $configAlgo, int $bcryptCost, int $argonMemoryKib, int $argonTimeCost, int $argonThreads): array {
		$wantArgon = $configAlgo === self::ALGO_ARGON2ID
			|| ($configAlgo === self::ALGO_AUTO && defined('PASSWORD_ARGON2ID'));
		if ($wantArgon && defined('PASSWORD_ARGON2ID')) {
			return [
				PASSWORD_ARGON2ID,
				[
					'memory_cost' => max(8, $argonMemoryKib),
					'time_cost' => max(1, $argonTimeCost),
					'threads' => max(1, $argonThreads),
				],
			];
		}
		return [PASSWORD_BCRYPT, ['cost' => min(31, max(4, $bcryptCost))]];
	}

	/** Called from HashTask on a worker thread. */
	public static function hash(string $password, string $configAlgo, int $bcryptCost, int $argonMemoryKib, int $argonTimeCost, int $argonThreads): string {
		[$algo, $options] = self::resolve($configAlgo, $bcryptCost, $argonMemoryKib, $argonTimeCost, $argonThreads);
		return password_hash($password, $algo, $options);
	}

	/** Called from HashTask on a worker thread. */
	public static function verify(string $password, string $hash): bool {
		return $hash !== '' && password_verify($password, $hash);
	}
}
