<?php

declare(strict_types=1);

namespace Auth;

use Auth\application\AuthService;
use Auth\application\captcha\CaptchaService;
use Auth\application\flow\AdministrationFlow;
use Auth\application\flow\CaptchaFlow;
use Auth\application\flow\CompletionFlow;
use Auth\application\flow\JoinFlow;
use Auth\application\flow\LoginFlow;
use Auth\application\flow\PasswordChangeFlow;
use Auth\application\flow\RegistrationFlow;
use Auth\application\flow\TwoFactorFlow;
use Auth\application\port\PlayerResolver;
use Auth\application\ratelimit\RateLimiter;
use Auth\application\session\SessionManager;
use Auth\application\support\Responder;
use Auth\command\CaptchaCommand;
use Auth\command\ChangePasswordCommand;
use Auth\command\LoginCommand;
use Auth\command\RegisterCommand;
use Auth\command\TwoFaCommand;
use Auth\config\AuthConfig;
use Auth\domain\password\PasswordPolicy;
use Auth\infrastructure\async\DbTask;
use Auth\infrastructure\async\HashTask;
use Auth\infrastructure\async\JobQueue;
use Auth\infrastructure\player\RestrictionListener;
use Auth\infrastructure\player\VisibilityFilter;
use Auth\infrastructure\storage\sqlite\SqliteAccountRepository;
use Auth\infrastructure\storage\sqlite\SqliteExecutor;
use pocketmine\api\plugin\Plugin;

/**
 * Composition root: the only place that knows concrete implementations.
 * Wires the DDD layers together and registers commands, listeners and the
 * visibility filter.
 */
final class Main extends Plugin {
	private ?AuthService $auth = null;

	public function onEnable(): void {
		$cfg = AuthConfig::load($this->getDataFolder());

		// pmmpthread workers cannot autoload: pre-load every class a task's
		// run() touches BEFORE the first submission (see docs/plugin-api §6).
		class_exists(DbTask::class);
		class_exists(HashTask::class);
		class_exists(SqliteExecutor::class);
		class_exists(PasswordPolicy::class);
		class_exists(\Auth\domain\password\PasswordHasher::class);

		if (!$cfg->enabled()) {
			$this->getLogger()->info('Auth is disabled in config.yml; staying passive.');
			return;
		}

		$dataFolder = rtrim($this->getDataFolder(), '/');
		if (!is_dir($dataFolder)) {
			mkdir($dataFolder, 0775, true);
		}

		// ---- ports & shared services -----------------------------------
		$sessions = new SessionManager();
		$policy = PasswordPolicy::fromConfigValues(
			$cfg->hashAlgorithm(),
			$cfg->bcryptCost(),
			$cfg->argonMemoryKib(),
			$cfg->argonTimeCost(),
			$cfg->argonThreads(),
		);
		$queue = new JobQueue($this->getThreadingPort(), $policy, $cfg->debug(), $this->getScheduler());
		$repository = new SqliteAccountRepository($queue, $dataFolder . '/' . $cfg->sqliteFile());
		$responder = new Responder($cfg, $cfg->debug());
		$resolver = $this->playerResolver();

		// ---- use-case flows (dependency order matters, it is acyclic) ---
		$limiter = new RateLimiter(
			$cfg->ratelimitEnabled(),
			$cfg->rlMaxPerIp(),
			$cfg->rlMaxPerName(),
			$cfg->rlBaseCooldown(),
			$cfg->rlMultiplier(),
			$cfg->rlMaxCooldown(),
		);
		$captchaService = new CaptchaService($cfg->captchaMode(), $cfg->captchaStyle(), $cfg->captchaLength());

		$completion = new CompletionFlow($sessions, $limiter, $cfg, $repository, $resolver, $responder, $this->getNetworkPort());
		$captchaFlow = new CaptchaFlow($sessions, $captchaService, $cfg, $responder, $resolver);
		$twoFactor = new TwoFactorFlow($sessions, $cfg, $repository, $queue, $responder, $resolver, $completion);
		$join = new JoinFlow($sessions, $cfg, $repository, $captchaFlow, $completion, $responder, $resolver, $this->getScheduler());
		$registration = new RegistrationFlow($sessions, $limiter, $cfg, $queue, $repository, $responder, $resolver, $completion, $captchaFlow, $twoFactor);
		$login = new LoginFlow($sessions, $limiter, $cfg, $queue, $responder, $resolver, $completion, $captchaFlow);
		$passwordChange = new PasswordChangeFlow($sessions, $cfg, $repository, $queue, $responder, $resolver);
		$administration = new AdministrationFlow($cfg, $repository, $queue, $responder);
		$administration->setOnlineLookup(fn(string $name) => \pocketmine\api\server\Server::getInstance()?->getPlayer($name));

		$this->auth = new AuthService($sessions, $cfg, $limiter, $join, $registration, $login, $captchaFlow, $twoFactor, $passwordChange, $administration);

		// ---- engine adapters ---------------------------------------------
		$this->registerListener($this->auth, $cfg);
		if ($cfg->hideUnauthenticated()) {
			// Per-viewer visibility (kernel filter): unauthenticated players
			// are hidden from other unauthenticated players. The kernel
			// handles RemoveEntity/AddEntity transitions automatically when
			// auth state flips; the filter itself is O(1) and stable.
			$this->setEntityVisibilityFilter(new VisibilityFilter($sessions));
		}

		// ---- commands ------------------------------------------------------
		foreach ([
			new RegisterCommand($this->auth),
			new LoginCommand($this->auth),
			new CaptchaCommand($this->auth),
			new ChangePasswordCommand($this->auth),
			new TwoFaCommand($this->auth),
			new \Auth\command\AdminCommand($this->auth),
		] as $command) {
			$this->registerCommand($command);
		}

		// Rate-limit memory pruning: rare sweep over tiny maps.
		$this->scheduleRepeatingTask(function () use ($cfg): void {
			$this->auth?->periodicPrune();
		}, max(200, $cfg->rlPruneIntervalTicks()));

		$this->getLogger()->info('Auth v' . $this->getVersion() . ' enabled (hash=' . $policy->describe() . ', db=' . $cfg->storageBackend() . ')');
	}

	public function onDisable(): void {
		// Pending worker futures are tracked by the kernel; the serial DB
		// queue simply drains whatever is already in flight. SQLite WAL mode
		// keeps the store consistent even if a job never lands.
		$this->getLogger()->info('Auth disabled');
	}

	public function auth(): AuthService {
		return $this->auth ?? throw new \LogicException('Auth service not initialized');
	}

	private function registerListener(AuthService $auth, AuthConfig $cfg): void {
		// Plugin::registerEvent() is protected - bind it into a closure the
		// listener can call.
		$plugin = $this;
		$subscribe = static function (string $class, callable $handler, int $priority = 2) use ($plugin): void {
			$plugin->registerEvent($class, $handler, $priority);
		};
		(new RestrictionListener($auth, $cfg, $subscribe))->registerAll();
	}

	/** PlayerResolver port implementation backed by the ECS directly. */
	private function playerResolver(): PlayerResolver {
		return new class implements PlayerResolver {
			public function byEntityId(int $entityId): ?\pocketmine\api\entity\Player {
				$world = \pocketmine\Kernel::getInstance()?->getWorld();
				if ($world === null) {
					return null;
				}
				$entity = $world->getEntity($entityId);
				if ($entity === null || !$entity->has(\pocketmine\core\component\tags\PlayerTag::class)) {
					return null;
				}
				// Server::getPlayerById() is broken upstream (calls
				// Entity::hasComponent), so resolve through the ECS here.
				return new \pocketmine\api\entity\Player(
					\pocketmine\core\ecs\EntityRef::create($entityId, $world),
					$world,
				);
			}
		};
	}
}
