<?php

declare(strict_types=1);

namespace Auth\domain;

/**
 * An account aggregate root. Immutable: state transitions return new
 * instances (withers), so flows can never mutate a snapshot someone else
 * holds. Pure domain - no engine, I/O or threading dependencies.
 */
final class Account {
	/**
	 * @param list<string>|null $backupCodeHashes sha256 hashes; plaintext
	 *        codes are never stored anywhere
	 */
	public function __construct(
		public readonly string $name,
		public readonly string $passwordHash,
		public readonly ?string $totpSecret,      // base32 or null
		public readonly bool $totpEnabled,
		public readonly ?array $backupCodeHashes,
		public readonly string $registerIp,
		public readonly int $registerTime,
		public readonly int $lastLoginTime,
		public readonly string $lastLoginIp,
		public readonly ?string $trustedIp,
		public readonly int $trustedUntil,
	) {}

	/** Hydrate from a raw storage row (column-name keyed). */
	public static function fromRow(array $row): self {
		return new self(
			(string)$row['name'],
			(string)$row['password_hash'],
			isset($row['totp_secret']) && is_string($row['totp_secret']) && $row['totp_secret'] !== '' ? $row['totp_secret'] : null,
			(bool)($row['totp_enabled'] ?? 0),
			isset($row['backup_codes']) && is_string($row['backup_codes']) && $row['backup_codes'] !== ''
				? (array)json_decode($row['backup_codes'], true)
				: null,
			(string)($row['register_ip'] ?? ''),
			(int)($row['register_time'] ?? 0),
			(int)($row['last_login_time'] ?? 0),
			(string)($row['last_login_ip'] ?? ''),
			isset($row['trusted_ip']) && is_string($row['trusted_ip']) && $row['trusted_ip'] !== '' ? $row['trusted_ip'] : null,
			(int)($row['trusted_until'] ?? 0),
		);
	}

	/** A brand-new, not-yet-persisted account. */
	public static function register(string $name, string $passwordHash, string $ip, int $now): self {
		return new self($name, $passwordHash, null, false, null, $ip, $now, 0, '', null, 0);
	}

	public function withPasswordHash(string $hash): self {
		return new self($this->name, $hash, $this->totpSecret, $this->totpEnabled, $this->backupCodeHashes, $this->registerIp, $this->registerTime, $this->lastLoginTime, $this->lastLoginIp, $this->trustedIp, $this->trustedUntil);
	}

	public function withTwoFactor(?string $base32Secret, bool $enabled, ?array $backupCodeHashes): self {
		return new self($this->name, $this->passwordHash, $base32Secret, $enabled, $backupCodeHashes, $this->registerIp, $this->registerTime, $this->lastLoginTime, $this->lastLoginIp, $this->trustedIp, $this->trustedUntil);
	}

	public function withLoginRecorded(string $ip, int $trustedUntil): self {
		return new self($this->name, $this->passwordHash, $this->totpSecret, $this->totpEnabled, $this->backupCodeHashes, $this->registerIp, $this->registerTime, time(), $ip, $ip, $trustedUntil);
	}

	// ---- business rules ------------------------------------------------

	/** Trusted-IP auto-login applies right now? */
	public function hasValidTrustFor(string $ip, int $now): bool {
		return $this->trustedIp === $ip && $this->trustedIp !== null && $this->trustedUntil > $now;
	}

	/** TOTP step must follow the password on this login? */
	public function requiresTotpNow(bool $featureOn, bool $required): bool {
		return $featureOn && $required && $this->totpEnabled;
	}
}
