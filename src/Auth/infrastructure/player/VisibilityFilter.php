<?php

declare(strict_types=1);

namespace Auth\infrastructure\player;

use Auth\application\session\SessionManager;
use pocketmine\port\driven\PlayerRef;

/**
 * Per-viewer entity visibility via the kernel's entity visibility filter
 * (registered with Plugin::registerEntityVisibilityFilter()).
 *
 * Rule: an unauthenticated viewer cannot see other unauthenticated players.
 * Everyone else (authenticated players, mobs, items) is always visible.
 *
 * NOTE ON TYPES: the docs say the filter receives (PlayerRef, EntityRef),
 * but NetworkSessionService::broadcastEntityStates() actually passes
 * (PlayerRef, pocketmine\core\ecs\Entity) - the raw ECS record from
 * World::getEntities(), which carries its id as a public $id property and
 * has NO getId() method. We therefore resolve the id defensively and fail
 * OPEN: any unexpected shape must never break the per-tick broadcast loop.
 *
 * The filter is called for every viewer->visible-entity pair during the
 * per-tick broadcast; both lookups are plain O(1) array isset()s against
 * the session map. Stability requirement (see PLUGIN.md): the answer for a
 * given pair only flips when one side authenticates, so clients get exactly
 * one despawn/respawn transition - no flicker.
 */
final class VisibilityFilter {
	public function __construct(private readonly SessionManager $sessions) {}

	/**
	 * Signature expected by NetworkSessionService:
	 *   fn(PlayerRef $viewer, pocketmine\core\ecs\Entity|EntityRef $target): bool
	 * Return false to suppress the target's state packets for this viewer.
	 */
	public function __invoke(PlayerRef $viewer, object $target): bool {
		try {
			if (!$this->sessions->isRestricted($viewer->entityId)) {
				return true; // authenticated viewers see everything
			}
			$targetId = property_exists($target, 'id') && is_int($target->id)
				? $target->id
				: (method_exists($target, 'getId') ? $target->getId() : null);
			if ($targetId === null) {
				return true; // unknown shape: fail open
			}
			// Hide other unauthenticated PLAYERS only; mobs/items are unaffected.
			return !($this->sessions->isTracked($targetId) && $this->sessions->isRestricted($targetId));
		} catch (\Throwable) {
			return true; // never break broadcastEntityStates
		}
	}
}
