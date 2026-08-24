<?php

declare(strict_types=1);

namespace Auth\config;

use pocketmine\api\plugin\Config;

/**
 * Typed view over config.yml. Defaults are merged under whatever the file
 * defines, so partial/outdated files never break the plugin.
 */
final class AuthConfig {
	public const DEFAULTS = [
		'auth' => [
			'enabled' => true,
			'debug' => false,
			'login-timeout-seconds' => 60,
			'min-password-length' => 6,
			'max-login-attempts' => 5,
			'hash-algorithm' => 'auto',
			'bcrypt-cost' => 12,
			'argon2-memory-kib' => 65536,
			'argon2-time-cost' => 4,
			'argon2-threads' => 2,
			'allow-chat' => false,
			'block-damage-to-unauthenticated' => true,
			'hide-unauthenticated-from-each-other' => true,
		],
		'twofa' => [
			'enabled' => true,
			'required' => true,
			'generate-on-register' => false,
			'period-seconds' => 30,
			'digits' => 6,
			'window' => 1,
			'issuer' => 'Khronos',
			'require-with-trusted-ip' => true,
			'backup-code-count' => 10,
		],
		'captcha' => [
			'mode' => 'after-failures',
			'style' => 'text',
			'length' => 5,
			'expires-seconds' => 90,
			'max-attempts' => 3,
			'trigger-after-failures' => 3,
		],
		'ratelimit' => [
			'enabled' => true,
			'max-attempts-per-ip' => 5,
			'max-attempts-per-name' => 5,
			'base-cooldown-seconds' => 30,
			'cooldown-multiplier' => 2.0,
			'max-cooldown-seconds' => 900,
			'decay-minutes' => 15,
			'prune-interval-ticks' => 12000,
		],
		'ip-autologin' => [
			'enabled' => true,
			'trust-minutes' => 60,
		],
		'storage' => [
			'backend' => 'sqlite',
			'sqlite-file' => 'accounts.sqlite',
		],
		'messages' => [
			'twofa-usage' => '&eUsage: &f/2fa <code>&e, &f/2fa enable&e, &f/2fa confirm <code>&e or &f/2fa disable <password>',
		],
	];

	private function __construct(private readonly Config $config) {}

	public static function load(string $dataFolder): self {
		return new self(new Config(rtrim($dataFolder, '/') . '/config.yml', self::DEFAULTS));
	}

	public function raw(): Config {
		return $this->config;
	}

	private function b(string $key, bool $default): bool {
		$v = $this->config->get($key, $default);
		return is_bool($v) ? $v : $default;
	}

	private function i(string $key, int $default): int {
		$v = $this->config->get($key, $default);
		return is_int($v) ? $v : (is_numeric($v) ? (int)$v : $default);
	}

	private function f(string $key, float $default): float {
		$v = $this->config->get($key, $default);
		return is_float($v) || is_int($v) ? (float)$v : $default;
	}

	private function s(string $key, string $default): string {
		$v = $this->config->get($key, $default);
		return is_string($v) ? $v : $default;
	}

	// ---- auth ----
	public function enabled(): bool { return $this->b('auth.enabled', true); }
	public function debug(): bool { return $this->b('auth.debug', false); }
	public function loginTimeoutSeconds(): int { return max(0, $this->i('auth.login-timeout-seconds', 60)); }
	public function minPasswordLength(): int { return max(1, $this->i('auth.min-password-length', 6)); }
	public function maxLoginAttempts(): int { return max(1, $this->i('auth.max-login-attempts', 5)); }
	public function hashAlgorithm(): string { return strtolower($this->s('auth.hash-algorithm', 'auto')); }
	public function bcryptCost(): int { return $this->i('auth.bcrypt-cost', 12); }
	public function argonMemoryKib(): int { return $this->i('auth.argon2-memory-kib', 65536); }
	public function argonTimeCost(): int { return $this->i('auth.argon2-time-cost', 4); }
	public function argonThreads(): int { return $this->i('auth.argon2-threads', 2); }
	public function allowChat(): bool { return $this->b('auth.allow-chat', false); }
	public function blockDamage(): bool { return $this->b('auth.block-damage-to-unauthenticated', true); }
	public function hideUnauthenticated(): bool { return $this->b('auth.hide-unauthenticated-from-each-other', true); }

	// ---- twofa ----
	public function totpEnabledFeature(): bool { return $this->b('twofa.enabled', true); }
	public function totpRequired(): bool { return $this->b('twofa.required', true); }
	public function totpOnRegister(): bool { return $this->b('twofa.generate-on-register', false); }
	public function totpPeriod(): int { return max(1, $this->i('twofa.period-seconds', 30)); }
	public function totpDigits(): int { return min(8, max(6, $this->i('twofa.digits', 6))); }
	public function totpWindow(): int { return max(0, $this->i('twofa.window', 1)); }
	public function totpIssuer(): string { return $this->s('twofa.issuer', 'Khronos'); }
	public function totpRequireWithTrustedIp(): bool { return $this->b('twofa.require-with-trusted-ip', true); }
	public function backupCodeCount(): int { return max(1, $this->i('twofa.backup-code-count', 10)); }

	// ---- captcha ----
	public function captchaMode(): string { return strtolower($this->s('captcha.mode', 'after-failures')); }
	public function captchaStyle(): string { return strtolower($this->s('captcha.style', 'text')); }
	public function captchaLength(): int { return $this->i('captcha.length', 5); }
	public function captchaExpiresSeconds(): int { return max(5, $this->i('captcha.expires-seconds', 90)); }
	public function captchaMaxAttempts(): int { return max(1, $this->i('captcha.max-attempts', 3)); }
	public function captchaTriggerAfterFailures(): int { return max(1, $this->i('captcha.trigger-after-failures', 3)); }

	// ---- ratelimit ----
	public function ratelimitEnabled(): bool { return $this->b('ratelimit.enabled', true); }
	public function rlMaxPerIp(): int { return max(1, $this->i('ratelimit.max-attempts-per-ip', 5)); }
	public function rlMaxPerName(): int { return max(1, $this->i('ratelimit.max-attempts-per-name', 5)); }
	public function rlBaseCooldown(): float { return max(1.0, $this->f('ratelimit.base-cooldown-seconds', 30.0)); }
	public function rlMultiplier(): float { return max(1.0, $this->f('ratelimit.cooldown-multiplier', 2.0)); }
	public function rlMaxCooldown(): int { return max(1, $this->i('ratelimit.max-cooldown-seconds', 900)); }
	public function rlDecayMinutes(): int { return max(1, $this->i('ratelimit.decay-minutes', 15)); }
	public function rlPruneIntervalTicks(): int { return max(200, $this->i('ratelimit.prune-interval-ticks', 12000)); }

	// ---- ip-autologin ----
	public function autoLoginEnabled(): bool { return $this->b('ip-autologin.enabled', true); }
	public function trustMinutes(): int { return max(1, $this->i('ip-autologin.trust-minutes', 60)); }

	// ---- storage ----
	public function storageBackend(): string { return strtolower($this->s('storage.backend', 'sqlite')); }
	public function sqliteFile(): string { return basename($this->s('storage.sqlite-file', 'accounts.sqlite')); }

	// ---- messages ----
	public function msg(string $key): string {
		$v = $this->config->get('messages.' . $key);
		if (is_string($v) && $v !== '') {
			return $v;
		}
		return (string)(self::DEFAULTS['messages'][$key] ?? '');
	}
}
