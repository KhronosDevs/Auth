<?php

declare(strict_types=1);

namespace Auth\domain;

/**
 * The stages of the authentication state machine a session walks through.
 * PHP enum: comparisons are identity checks on singletons - same cost as
 * int comparison, but type-safe and self-documenting.
 */
enum AuthStage {
	/** Account row is being fetched; no prompts yet. */
	case Loading;
	/** A captcha must be solved before anything else. */
	case Captcha;
	/** Awaiting /login or /register. */
	case Password;
	/** Password accepted; awaiting TOTP/backup code. */
	case TwoFactor;
	/** Fully authenticated. */
	case Authenticated;
}
