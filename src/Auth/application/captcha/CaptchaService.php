<?php

declare(strict_types=1);

namespace Auth\application\captcha;

use Auth\domain\captcha\Challenge;
use Random\Engine\Secure;
use Random\Randomizer;

/**
 * Produces chat-delivered captcha challenges. The 0.15.10 protocol has no
 * graphical UI packets, so challenges are text (typed code) or arithmetic.
 * Pure generation - expiry/attempt policy lives in the session + flow.
 */
final class CaptchaService {
	public const MODE_OFF = 'off';
	public const MODE_ALWAYS = 'always';
	public const MODE_AFTER_FAILURES = 'after-failures';

	public const STYLE_TEXT = 'text';
	public const STYLE_MATH = 'math';

	/** Ambiguity-free charset (no 0/O/1/I/L). */
	private const CHARSET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

	private Randomizer $rng;

	public function __construct(
		private readonly string $mode,
		private readonly string $style,
		private readonly int $length,
	) {
		$this->rng = new Randomizer(new Secure());
	}

	public function mode(): string {
		return $this->mode;
	}

	public function isEnabled(): bool {
		return $this->mode !== self::MODE_OFF;
	}

	/** Should this session be challenged right now? */
	public function isDueFor(int $failedLogins, int $triggerAfterFailures): bool {
		return match ($this->mode) {
			self::MODE_ALWAYS => true,
			self::MODE_AFTER_FAILURES => $failedLogins >= max(1, $triggerAfterFailures),
			default => false,
		};
	}

	/** Generate a fresh challenge. */
	public function generate(): Challenge {
		if ($this->style === self::STYLE_MATH) {
			$a = $this->rng->getInt(2, 12);
			$b = $this->rng->getInt(2, 12);
			return new Challenge("$a + $b", (string)($a + $b));
		}
		$code = '';
		$max = strlen(self::CHARSET) - 1;
		for ($i = 0; $i < max(3, $this->length); ++$i) {
			$code .= self::CHARSET[$this->rng->getInt(0, $max)];
		}
		return new Challenge($code, $code);
	}
}
