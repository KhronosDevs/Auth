<?php

declare(strict_types=1);

namespace Auth\application\flow;

use Auth\domain\AccountRepository;
use Auth\application\port\PasswordEncoder;
use Auth\application\port\PlayerResolver;
use Auth\application\session\AuthSession;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\config\AuthConfig;
use Auth\domain\AuthStage;
use pocketmine\api\entity\Player;

/**
 * /changepassword <old> <new>: verifies the current password off-thread,
 * then hashes and persists the new one.
 */
final class PasswordChangeFlow {
	public function __construct(
		private readonly SessionManager $sessions,
		private readonly AuthConfig $cfg,
		private readonly AccountRepository $accounts,
		private readonly PasswordEncoder $encoder,
		private readonly Responder $responder,
		private readonly PlayerResolver $resolver,
	) {}

	/** Returns true when the input was handled. */
	public function handleCommand(Player $player, array $args): bool {
		$session = $this->sessions->get($player->getId());
		if ($session === null) {
			return false;
		}
		if (count($args) < 2) {
			$this->responder->key($player, 'changepw-usage');
			return true;
		}
		if ($session->stage !== AuthStage::Authenticated) {
			return true; // unauthenticated: silently swallowed by command gating
		}
		[$old, $new] = [(string)$args[0], (string)$args[1]];
		if (strlen($new) < $this->cfg->minPasswordLength()) {
			$this->responder->key($player, 'changepw-short', ['{min}' => (string)$this->cfg->minPasswordLength()]);
			return true;
		}
		$account = $session->account;
		if ($account === null) {
			$this->responder->key($player, 'login-notregistered');
			return true;
		}

		$this->encoder->verify($old, $account->passwordHash, function (bool $ok) use ($session, $new): void {
			if ($this->sessions->get($session->entityId) === null) {
				return;
			}
			if (!$ok) {
				$this->responder->key($this->resolver->byEntityId($session->entityId), 'changepw-wrongold');
				return;
			}
			$this->encoder->hash($new, function (string $hash) use ($session): void {
				$this->accounts->updatePasswordHash($session->name, $hash, function () use ($session, $hash): void {
					$session->account = $session->account?->withPasswordHash($hash);
					$this->responder->key($this->resolver->byEntityId($session->entityId), 'changepw-ok');
				});
			});
		});
		return true;
	}
}
