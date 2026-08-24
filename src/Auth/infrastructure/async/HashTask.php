<?php

declare(strict_types=1);

namespace Auth\infrastructure\async;

use Auth\domain\password\PasswordHasher;
use pocketmine\adapter\driven\threading\PluginTask;

/**
 * Password hashing/verification on a pool worker thread. bcrypt (and
 * Argon2id when the build gains it) cost hundreds of milliseconds - never
 * run them on the main thread.
 */
final class HashTask extends PluginTask {
	public const MODE_HASH = 'hash';
	public const MODE_VERIFY = 'verify';

	public string $mode = self::MODE_HASH;
	public string $password = '';
	/** Existing hash for MODE_VERIFY. */
	public string $hash = '';
	/** Hashing parameters (mirrors AuthConfig). */
	public string $algo = 'auto'; // PasswordPolicy::ALGO_AUTO
	public int $bcryptCost = 12;
	public int $argonMemoryKib = 65536;
	public int $argonTimeCost = 4;
	public int $argonThreads = 2;
	/** Results: MODE_VERIFY -> "1"/"0"; MODE_HASH -> the hash string. */
	public string $result = '';
	/** Non-empty when the operation failed (exceptions cannot cross pmmpthread). */
	public string $error = '';

	public function run(): void {
		try {
			if ($this->mode === self::MODE_VERIFY) {
				$this->result = PasswordHasher::verify($this->password, $this->hash) ? '1' : '0';
				$this->complete($this->result === '1');
			} else {
				$this->result = PasswordHasher::hash(
					$this->password,
					$this->algo,
					$this->bcryptCost,
					$this->argonMemoryKib,
					$this->argonTimeCost,
					$this->argonThreads,
				);
				$this->complete($this->result);
			}
		} catch (\Throwable $e) {
			// Exceptions cannot cross pmmpthread - see DbTask.
			$this->error = get_class($e) . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine();
			$this->complete(null);
		}
	}
}
