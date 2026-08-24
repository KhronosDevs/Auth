<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\application\port\PlayerResolver;
use Auth\application\ratelimit\RateLimiter;
use Auth\application\session\AuthSession;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\AccountRepository;
use pocketmine\protocol\MovePlayerPacket;
use pocketmine\port\driven\NetworkPort;

/**
 * The moment authentication succeeds: lift restrictions, cancel the timeout,
 * clear brute-force counters, refresh the trusted-IP window, and snap the
 * client onto the authoritative position.
 */
final class CompletionFlow {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly RateLimiter $limiter,
		private readonly AuthConfig $cfg,
		private readonly AccountRepository $accounts,
		private readonly PlayerResolver $resolver,
		private readonly Responder $responder,
		private readonly NetworkPort $network,
	) {}

	public function complete(AuthSession $session, bool $announce = true): void {
		$this->sessions->markAuthenticated($session);
		$session->timeoutHandler?->cancel();
		$session->timeoutHandler = null;
		$this->limiter->success($session->ip, $session->name);

		if ($this->cfg->autoLoginEnabled() && ($account = $session->account) !== null) {
			$until = time() + $this->cfg->trustMinutes() * 60;
			$this->accounts->recordLogin($session->name, $session->ip, $until, fn() => null);
			// Optimistic local update so later reads see fresh trust without
			// waiting for the async write.
			$session->account = $account->withLoginRecorded($session->ip, $until);
		}

		$player = $this->resolver->byEntityId($session->entityId);
		if ($player === null) {
			return;
		}
		if ($announce) {
			$this->responder->key($player, 'login-ok', ['{player}' => $player->getName()]);
		}
		// Visibility flips are handled by the kernel's entity visibility
		// filter (registered in Main): newly-visible players get a fresh
		// AddPlayerPacket automatically. Resync the frozen position.
		$this->resyncPosition($session);
	}

	/**
	 * Snap the client onto the authoritative server position (MODE_RESET).
	 * The per-move freeze snap-back lives inside the kernel's handleMove
	 * (cancelled PlayerMoveEvent -> sendTeleportTo); this one-shot exists to
	 * release a session that was frozen while unauthenticated.
	 */
	private function resyncPosition(AuthSession $session): void {
		$player = $this->resolver->byEntityId($session->entityId);
		if ($player === null) {
			return;
		}
		$pos = $player->getPosition();
		$rot = $player->getRotation();
		$pk = new MovePlayerPacket();
		$pk->eid = 0; // protocol 84: self is always eid 0 on the wire
		$pk->x = $pos->x;
		$pk->y = $pos->y;
		$pk->z = $pos->z;
		$pk->yaw = $rot->yaw;
		$pk->bodyYaw = $rot->yaw;
		$pk->pitch = $rot->pitch;
		$pk->mode = MovePlayerPacket::MODE_RESET;
		$pk->onGround = true;
		$this->network->sendPacket($session->ref, $pk);
	}
}
