<?php

declare(strict_types=1);

namespace Auth\domain\twofactor;

/**
 * A TOTP shared secret value object. Wraps the raw 20-byte secret and its
 * base32 representation; generation and otpauth URI construction live here
 * so flows never touch encoding details.
 */
final class TotpSecret {
	private function __construct(
		public readonly string $raw,
		public readonly string $base32,
	) {}

	public static function generate(): self {
		$raw = random_bytes(20); // 160 bits - the standard Google Authenticator size
		return new self($raw, Base32::encode($raw));
	}

	public static function fromBase32(string $base32): self {
		return new self(Base32::decode($base32), $base32);
	}

	/** The URI accepted by Google Authenticator / Authy import flows. */
	public function otpauthUri(string $accountName, string $issuer, int $digits, int $periodSeconds): string {
		$params = http_build_query([
			'secret' => $this->base32,
			'issuer' => $issuer,
			'algorithm' => 'SHA1',
			'digits' => $digits,
			'period' => $periodSeconds,
		]);
		return 'otpauth://totp/' . rawurlencode($issuer . ':' . $accountName) . '?' . $params;
	}

	/** Secret formatted in 4-char groups for manual entry into an app. */
	public function grouped(): string {
		return chunk_split($this->base32, 4, ' ');
	}
}
