<?php

declare(strict_types=1);

namespace Auth\application\ratelimit;

/**
 * Brute-force protection: per-IP and per-username failure tracking with
 * escalating cooldowns and self-pruning memory.
 *
 * Structures are flat string-keyed arrays with O(1) lookups; the prune
 * sweep runs on a scheduler task (not per event) so hot paths never pay
 * cleanup costs.
 */
final class RateLimiter {
	/** @var array<string, array{fails: int, lockedUntil: int, level: int, lastSeen: int}> */
	private array $byIp = [];
	/** @var array<string, array{fails: int, lockedUntil: int, level: int, lastSeen: int}> */
	private array $byName = [];

	public function __construct(
		private readonly bool $enabled,
		private readonly int $maxPerIp,
		private readonly int $maxPerName,
		private readonly float $baseCooldownSeconds,
		private readonly float $cooldownMultiplier,
		private readonly int $maxCooldownSeconds,
	) {}

	/**
	 * Check whether an attempt may proceed right now.
	 * @return array{0: bool, 1: int} [allowed, retryAfterSeconds]
	 */
	public function check(string $ip, string $name): array {
		if (!$this->enabled) {
			return [true, 0];
		}
		$now = time();
		foreach ([$this->byIp[$ip] ?? null, $this->byName[strtolower($name)] ?? null] as $entry) {
			if ($entry !== null && $entry['lockedUntil'] > $now) {
				return [false, $entry['lockedUntil'] - $now];
			}
		}
		return [true, 0];
	}

	/** Record a failed attempt; may arm/escalate a cooldown. */
	public function failure(string $ip, string $name): void {
		if (!$this->enabled) {
			return;
		}
		$now = time();
		$this->bump($this->byIp, $ip, $this->maxPerIp, $now);
		$this->bump($this->byName, strtolower($name), $this->maxPerName, $now);
	}

	/** Successful authentication clears the failure memory for this identity. */
	public function success(string $ip, string $name): void {
		unset($this->byIp[$ip], $this->byName[strtolower($name)]);
	}

	/**
	 * Drop entries that expired (decay window passed, no active lock).
	 * Called from a periodic task - never from hot paths.
	 */
	public function prune(int $decaySeconds): void {
		$cutoff = time() - $decaySeconds;
		foreach (['ip' => $this->byIp, 'name' => $this->byName] as $which => $map) {
			foreach ($map as $key => $entry) {
				if ($entry['lastSeen'] < $cutoff && $entry['lockedUntil'] <= time()) {
					unset($map[$key]);
				}
			}
			if ($which === 'ip') {
				$this->byIp = $map;
			} else {
				$this->byName = $map;
			}
		}
	}

	/** @param array<string, array{fails: int, lockedUntil: int, level: int, lastSeen: int}> $map */
	private function bump(array &$map, string $key, int $threshold, int $now): void {
		$entry = $map[$key] ?? ['fails' => 0, 'lockedUntil' => 0, 'level' => 0, 'lastSeen' => $now];
		$entry['fails']++;
		$entry['lastSeen'] = $now;
		if ($entry['fails'] >= $threshold) {
			// Escalate once per threshold-crossing batch: base * mult^level.
			$cooldown = (int)min(
				$this->maxCooldownSeconds,
				ceil($this->baseCooldownSeconds * ($this->cooldownMultiplier ** $entry['level'])),
			);
			$entry['lockedUntil'] = max($entry['lockedUntil'], $now + $cooldown);
			$entry['level']++;
			$entry['fails'] = 0; // restart the counter inside this lock level
		}
		$map[$key] = $entry;
	}
}
