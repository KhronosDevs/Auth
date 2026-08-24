<?php

declare(strict_types=1);

namespace Auth\domain\twofactor;

/**
 * An immutable set of single-use backup codes, stored as hashes (the codes
 * themselves are random, so a cheap deterministic hash is sufficient and
 * keeps verification off the expensive password-hash path).
 */
final class BackupCodeSet {
	/** @param list<string> $hashes sha256 hashes */
	private function __construct(private readonly array $hashes) {}

	/**
	 * Generate codes AND keep their plaintext for one-time display.
	 *
	 * @return array{self, list<string>} [hashed set, plaintext codes]
	 */
	public static function issue(int $count): array {
		$codes = [];
		for ($i = 0; $i < max(1, $count); ++$i) {
			$codes[] = self::randomCode();
		}
		return [new self(array_map(self::hash(...), $codes)), $codes];
	}

	/** @param list<string> $hashes */
	public static function fromHashes(array $hashes): self {
		return new self(array_values($hashes));
	}

	/** @return list<string> */
	public function hashes(): array {
		return $this->hashes;
	}

	public function isEmpty(): bool {
		return $this->hashes === [];
	}

	/**
	 * Constant-time match against any code in the set.
	 *
	 * @return int|null the matched index (for burning), or null
	 */
	public function match(string $code): ?int {
		$hash = self::hash($code);
		foreach ($this->hashes as $i => $h) {
			if (is_string($h) && hash_equals($h, $hash)) {
				return $i;
			}
		}
		return null;
	}

	/** The set with the given index consumed. */
	public function burn(int $index): self {
		$hashes = $this->hashes;
		unset($hashes[$index]);
		return new self(array_values($hashes));
	}

	private static function randomCode(): string {
		$part = static function (): string {
			$out = '';
			for ($i = 0; $i < 4; ++$i) {
				$out .= '23456789ABCDEFGHJKMNPQRSTUVWXYZ'[random_int(0, 30)];
			}
			return $out;
		};
		return $part() . '-' . $part();
	}

	private static function hash(string $code): string {
		return hash('sha256', 'khronos-2fa-backup:' . $code);
	}
}
