<?php

declare(strict_types=1);

namespace Auth\infrastructure\player;

use Auth\application\AuthService;
use Auth\config\AuthConfig;
use pocketmine\api\event\BlockBreakEvent;
use pocketmine\api\event\BlockPlaceEvent;
use pocketmine\api\event\CancellableEvent;
use pocketmine\api\event\DataPacketReceiveEvent;
use pocketmine\api\event\EntityDamageEvent;
use pocketmine\api\event\EventPriority;
use pocketmine\api\event\InventoryOpenEvent;
use pocketmine\api\event\InventoryTransactionEvent;
use pocketmine\api\event\PlayerChatEvent;
use pocketmine\api\event\PlayerCommandPreprocessEvent;
use pocketmine\api\event\PlayerDropItemEvent;
use pocketmine\api\event\PlayerInteractEvent;
use pocketmine\api\event\PlayerJoinEvent;
use pocketmine\api\event\PlayerLeaveEvent;
use pocketmine\api\event\PlayerMoveEvent;
use pocketmine\api\event\PlayerQuitEvent;

/**
 * Registers every event gate for unauthenticated players.
 *
 * All checks are a single O(1) isset() against the restricted-session map -
 * authenticated players pay one array lookup per event and nothing else.
 */
final class RestrictionListener {
	/** Commands an unauthenticated player may always use. */
	private const ALLOWED_COMMANDS = ['register', 'login', 'captcha'];

	public function __construct(
		private readonly AuthService $auth,
		private readonly AuthConfig $cfg,
		/** fn(string $eventClass, callable $handler, int $priority): void - bound Plugin::registerEvent */
		private readonly \Closure $subscribe,
	) {}

	public function registerAll(): void {
		$auth = $this->auth;
		$subscribe = $this->subscribe;

		// ---- lifecycle -------------------------------------------------
		$subscribe(PlayerJoinEvent::class, static function (PlayerJoinEvent $event) use ($auth): void {
			$auth->handleJoin($event);
		}, EventPriority::LOWEST); // run before other plugins announce the join

		// The server fires BOTH PlayerLeaveEvent and PlayerQuitEvent; both
		// handlers are idempotent (session removal cancels the timeout task).
		$subscribe(PlayerLeaveEvent::class, static function (PlayerLeaveEvent $event) use ($auth): void {
			$auth->handleQuit($event->getPlayer()->getId());
		});
		$subscribe(PlayerQuitEvent::class, static function (PlayerQuitEvent $event) use ($auth): void {
			$auth->handleQuit($event->getPlayer()->getId());
		});

		// ---- chat / commands -------------------------------------------
		if (!$this->cfg->allowChat()) {
			$subscribe(PlayerChatEvent::class, static function (PlayerChatEvent $event) use ($auth): void {
				if ($auth->sessions()->isRestricted($event->getPlayer()->getId())) {
					$event->setCancelled(true);
				}
			}, EventPriority::HIGHEST);
		}

		$subscribe(PlayerCommandPreprocessEvent::class, static function (PlayerCommandPreprocessEvent $event) use ($auth): void {
			if (!$auth->sessions()->isRestricted($event->getPlayer()->getId())) {
				return;
			}
			$command = ltrim($event->getCommand(), '/');
			$name = strtolower(strtok($command, ' ') ?: '');
			if (!in_array($name, self::ALLOWED_COMMANDS, true)) {
				$event->setCancelled(true);
			}
		}, EventPriority::HIGHEST);

		// ---- world interaction -----------------------------------------
		foreach ([BlockBreakEvent::class, BlockPlaceEvent::class, PlayerInteractEvent::class, PlayerDropItemEvent::class] as $class) {
			$subscribe($class, static function (CancellableEvent $event) use ($auth): void {
				/** @var CancellableEvent&object{getPlayer(): \pocketmine\api\entity\Player} $event */
				if ($auth->sessions()->isRestricted($event->getPlayer()->getId())) {
					$event->setCancelled(true);
				}
			}, EventPriority::HIGHEST);
		}

		$subscribe(InventoryTransactionEvent::class, static function (InventoryTransactionEvent $event) use ($auth): void {
			if ($auth->sessions()->isRestricted($event->getPlayer()->getId())) {
				$event->setCancelled(true);
			}
		}, EventPriority::HIGHEST);

		// Cancelling the open prevents the ContainerOpenPacket entirely, so
		// unauthenticated players never see chest/furnace lids open.
		$subscribe(InventoryOpenEvent::class, static function (InventoryOpenEvent $event) use ($auth): void {
			if ($auth->sessions()->isRestricted($event->getPlayer()->getId())) {
				$event->setCancelled(true);
			}
		}, EventPriority::HIGHEST);

		// ---- movement ----------------------------------------------------
		// Freezing is done through the cancellable PlayerMoveEvent: the
		// kernel emits it BEFORE applying the move and, on cancellation,
		// rejects the move and rubber-bands the client to the authoritative
		// position (same mechanism as its anti-cheat violations). This is
		// the single source of truth for movement gating.
		$subscribe(PlayerMoveEvent::class, static function (PlayerMoveEvent $event) use ($auth): void {
			if ($auth->sessions()->isRestricted($event->getPlayer()->getId())) {
				$event->setCancelled(true);
			}
		}, EventPriority::HIGHEST);

		// ---- damage protection ------------------------------------------
		if ($this->cfg->blockDamage()) {
			$subscribe(EntityDamageEvent::class, static function (EntityDamageEvent $event) use ($auth): void {
				$entity = $event->getEntity();
				if ($entity instanceof \pocketmine\api\entity\Player
					&& $auth->sessions()->isRestricted($entity->getId())
				) {
					$event->setCancelled(true);
				}
			}, EventPriority::HIGHEST);
		}
	}
}
