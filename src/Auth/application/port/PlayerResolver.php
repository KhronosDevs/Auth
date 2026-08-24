<?php

declare(strict_types=1);

namespace Auth\application\port;

use pocketmine\api\entity\Player;

/**
 * Resolves an entity id to its live Player facade (null when the player has
 * left). Implemented in the composition root; deliberately NOT
 * Server::getPlayerById(), which is broken upstream (Entity::hasComponent).
 */
interface PlayerResolver {
	public function byEntityId(int $entityId): ?Player;
}
