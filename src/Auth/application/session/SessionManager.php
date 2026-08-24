<?php

declare(strict_types=1);

namespace Auth\application\session;

use Auth\domain\AuthStage;
use pocketmine\port\driven\PlayerRef;

/**
 * Registry of per-player authentication sessions.
 *
 * HOT-PATH CONTRACT: restriction checks are a single isset() against the
 * int-keyed $restricted map - O(1), zero allocations, zero I/O. The map is
 * maintained on state transitions (join/auth/quit), never queried from
 * storage. Storage is hit exactly once per join (asynchronously).
 */
final class SessionManager {
	/** @var array<int, AuthSession> entityId => session (all tracked players) */
	private array $all = [];
	/** @var array<int, AuthSession> entityId => session (restricted only) */
	private array $restricted = [];

	public function create(int $entityId, string $name, string $uuid, string $ip, PlayerRef $ref): AuthSession {
		$session = new AuthSession($entityId, $name, $uuid, $ip, $ref);
		$this->all[$entityId] = $session;
		$this->restricted[$entityId] = $session;
		return $session;
	}

	/** The hot path: is this entity locked behind authentication? */
	public function isRestricted(int $entityId): bool {
		return isset($this->restricted[$entityId]);
	}

	/** Is this entityId one of our tracked players? (visibility-filter target test) */
	public function isTracked(int $entityId): bool {
		return isset($this->all[$entityId]);
	}

	public function get(int $entityId): ?AuthSession {
		return $this->all[$entityId] ?? null;
	}

	/** @return array<int, AuthSession> restricted sessions only (tiny) */
	public function restrictedSessions(): array {
		return $this->restricted;
	}

	/** Mark authenticated: leaves the restriction map (O(1)). */
	public function markAuthenticated(AuthSession $session): void {
		$session->stage = AuthStage::Authenticated;
		unset($this->restricted[$session->entityId]);
	}

	public function remove(int $entityId): void {
		if (isset($this->all[$entityId])) {
			$this->all[$entityId]->timeoutHandler?->cancel();
			unset($this->all[$entityId], $this->restricted[$entityId]);
		}
	}
}
