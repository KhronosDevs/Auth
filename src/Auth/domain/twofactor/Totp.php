<?php

declare(strict_types=1);

namespace Auth\domain\twofactor;

/**
 * RFC 6238 TOTP (HMAC-SHA1, the Google Authenticator profile).
 *
 * Cheap (~microseconds) so it runs on the main thread; pure static functions
 * with no I/O, isolated here so it can move to a worker later if profiling
 * ever demands it.
 */
final class Totp {
	/** The numeric code for a binary secret at a given timestamp. */
	public static function at(string $binarySecret, int $unixTime, int $periodSeconds, int $digits): string {
		$counter = intdiv($unixTime, max(1, $periodSeconds));
		$counterBin = pack('N2', ($counter >> 32) & 0xFFFFFFFF, $counter & 0xFFFFFFFF);
		$hmac = hash_hmac('sha1', $counterBin, $binarySecret, true);
		$offset = ord($hmac[strlen($hmac) - 1]) & 0x0F;
		$code = ((ord($hmac[$offset]) & 0x7F) << 24)
			| ((ord($hmac[$offset + 1]) & 0xFF) << 16)
			| ((ord($hmac[$offset + 2]) & 0xFF) << 8)
			| (ord($hmac[$offset + 3]) & 0xFF);
		return str_pad((string)($code % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
	}

	/**
	 * Constant-time verification with +/- $window periods of clock-skew
	 * tolerance. Backup-code matching is BackupCodeSet's job, not this
	 * class's.
	 */
	public static function matches(string $binarySecret, string $code, int $unixTime, int $periodSeconds, int $digits, int $window): bool {
		if ($binarySecret === '') {
			return false;
		}
		for ($delta = -$window; $delta <= $window; ++$delta) {
			if (hash_equals(self::at($binarySecret, $unixTime + ($delta * $periodSeconds), $periodSeconds, $digits), $code)) {
				return true;
			}
		}
		return false;
	}
}
