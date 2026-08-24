<?php

declare(strict_types=1);

namespace Auth\domain\twofactor;

/**
 * RFC 4648 base32 (A-Z, 2-7), used for TOTP shared secrets.
 * Pure static functions - safe on any thread.
 */
final class Base32 {
	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function encode(string $bytes): string {
		$out = '';
		$bits = 0;
		$value = 0;
		for ($i = 0, $n = strlen($bytes); $i < $n; ++$i) {
			$value = ($value << 8) | ord($bytes[$i]);
			$bits += 8;
			while ($bits >= 5) {
				$out .= self::ALPHABET[($value >> ($bits - 5)) & 31];
				$bits -= 5;
			}
		}
		if ($bits > 0) {
			$out .= self::ALPHABET[($value << (5 - $bits)) & 31];
		}
		return $out;
	}

	/** Decode a base32 string; invalid characters are ignored (apps may add spaces). */
	public static function decode(string $encoded): string {
		$encoded = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $encoded));
		$out = '';
		$bits = 0;
		$value = 0;
		for ($i = 0, $n = strlen($encoded); $i < $n; ++$i) {
			$pos = strpos(self::ALPHABET, $encoded[$i]);
			if ($pos === false) {
				continue;
			}
			$value = ($value << 5) | $pos;
			$bits += 5;
			if ($bits >= 8) {
				$out .= chr(($value >> ($bits - 8)) & 255);
				$bits -= 8;
			}
		}
		return $out;
	}
}
