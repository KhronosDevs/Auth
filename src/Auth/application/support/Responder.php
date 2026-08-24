<?php

declare(strict_types=1);

namespace Auth\application\support;

use Auth\config\AuthConfig;
use pocketmine\utils\TextFormat;

/**
 * Message rendering + delivery for flows. Flows speak in config-message KEYS;
 * this service resolves text, applies placeholders, prefix & color codes,
 * and delivers through Player::sendMessage(), which routes through
 * NetworkSessionService::sendTextTo() - the framed batch pipeline that
 * protocol-84 clients actually accept.
 */
final class Responder {
	public function __construct(
		private readonly AuthConfig $cfg,
		private readonly bool $debug = false,
	) {}

	/** Send a configured message (by key) with placeholder substitutions. */
	public function key(object|null $to, string $key, array $replacements = []): void {
		if ($to === null || $key === '') {
			return;
		}
		$text = strtr($this->cfg->msg($key), $replacements);
		if ($text === '') {
			return;
		}
		$this->dbg('send to ' . (method_exists($to, 'getName') ? $to->getName() : get_class($to)) . ': ' . substr($text, 0, 48));
		$to->sendMessage($this->colorize($text));
	}

	public function colorize(string $message): string {
		return TextFormat::colorize($this->cfg->msg('prefix')) . TextFormat::colorize($message);
	}

	public function dbg(string $message): void {
		if ($this->debug) {
			error_log('[Auth][trace] ' . $message);
		}
	}
}
