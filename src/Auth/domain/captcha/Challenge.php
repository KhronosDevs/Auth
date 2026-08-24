<?php

declare(strict_types=1);

namespace Auth\domain\captcha;

/**
 * A captcha challenge value object: what the player sees and what must be
 * typed back. Immutable; expiry/attempts tracking lives in the session.
 */
final class Challenge {
	public function __construct(
		public readonly string $question, // "7 + 5" or "XJ4K9"
		public readonly string $answer,
	) {}
}
