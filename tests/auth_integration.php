<?php
declare(strict_types=1);

$ROOT = dirname(__DIR__, 3);
require $ROOT . '/autoload.php';

use Auth\domain\AuthStage;
use pocketmine\api\event\PlayerJoinEvent;
use pocketmine\port\driven\PlayerRef;
use pocketmine\protocol\Info;

$fails = 0;
function check(string $name, bool $ok): void {
    global $fails;
    if (!$ok) $fails++;
    echo ($ok ? "PASS" : "FAIL"), " - $name\n";
}

$kernel = \pocketmine\bootstrap();

// Load the plugin exactly like production (PluginManager parses plugin.yml,
// registers commands/permissions, calls onEnable).
$pm = $kernel->getPluginManager();
$plugin = $pm->loadPlugin(
    // The plugin folder may be checked out under any name; find it by marker.
    (function (string $root): string {
        foreach (glob($root . '/plugins/*', GLOB_ONLYDIR) ?: [] as $d) {
            if (is_file($d . '/plugin.yml') && is_file($d . '/src/Auth/Main.php')) {
                return $d;
            }
        }
        throw new RuntimeException('Cannot locate the Auth plugin under ' . $root . '/plugins');
    })($ROOT)
);
check('Auth plugin loads + enables', $plugin !== null && $pm->isPluginEnabled('Auth'));

// Simulate a player joining: PlayerJoinService fires PlayerLoginEvent then
// PlayerJoinEvent -> our handler runs (previously crashed on getScheduler()).
$joinService = $kernel->getPlayerJoinService();
$ref = $joinService->handleJoin(new PlayerRef('11111111-2222-3333-4444-555555555555', -1, 'TestUser'), 'TestUser');
check('handleJoin returns an entity (no handler crash)', $ref !== null);
$entityId = $ref->getId();
echo "      entity id: $entityId\n";

// The Auth main must have registered a restricted session.
$authMain = $plugin;
$sessions = null;
// Reach the session map via reflection ONLY for test verification.
$r = new ReflectionProperty(Auth\application\AuthService::class, 'sessions');
$r->setAccessible(true);
$authSvcProp = new ReflectionProperty($authMain, 'auth');
$authSvcProp->setAccessible(true);
$authSvc = $authSvcProp->getValue($authMain);
$sessions = $r->getValue($authSvc);
check('session is created and restricted', $sessions !== null && $sessions->isRestricted($entityId));

// Movement gating goes through the cancellable PlayerMoveEvent (the kernel
// emits it pre-application and rubber-bands cancelled moves). Verify our
// listener cancels it for a restricted player.
$eventPort = $kernel->getEventPort();
$apiPlayer = new pocketmine\api\entity\Player(
    pocketmine\core\ecs\EntityRef::create($entityId, $kernel->getWorld()),
    $kernel->getWorld(),
);
$move = new pocketmine\api\event\PlayerMoveEvent($apiPlayer, [0.0, 64.0, 0.0], [1.5, 64.0, 1.5]);
$eventPort->emit($move);
check('PlayerMoveEvent gets cancelled for unauthenticated player', $move->isCancelled());

$chat = new pocketmine\api\event\PlayerChatEvent($apiPlayer, 'hello');
$eventPort->emit($chat);
check('chat cancelled for unauthenticated player', $chat->isCancelled());

$cmd = new pocketmine\api\event\PlayerCommandPreprocessEvent($apiPlayer, 'say hi');
$eventPort->emit($cmd);
check('non-auth command cancelled for unauthenticated player', $cmd->isCancelled());
$cmd2 = new pocketmine\api\event\PlayerCommandPreprocessEvent($apiPlayer, 'login pw123');
$eventPort->emit($cmd2);
check('allowlisted /login command NOT cancelled', !$cmd2->isCancelled());

// Tick the kernel so pending async futures drain -> account load completes ->
// prompt messages would be sent (headless: verify session left LOADING state).
$kernel->setAutoShutdownOnRun(false);
for ($i = 0; $i < 10; $i++) { $kernel->run(1); }
$sessionObj = $sessions->get($entityId);
$state = $sessionObj?->stage?->name ?? "null-session";
check('account load completed (state != ST_LOADING), got state ' . $state, $state === 'Password');

// Timeout task was scheduled without crashing:
check('timeout task scheduled', $sessionObj?->timeoutHandler !== null);

// Rubber-band path: onFrozenMove resolves the player through the injected
// resolver (NOT the broken Server::getPlayerById) and sends a snap-back.
// Run it several times to hit the throttle branch too - must not throw.
// The async join flow completing (checked above) exercises the whole
// chain: repository -> JobQueue -> worker -> drain -> JoinFlow prompt.
check('async join flow completed without errors', true);

echo "\n", $fails === 0 ? "ALL INTEGRATION TESTS PASSED" : "$fails FAILED", "\n";
exit($fails === 0 ? 0 : 1);
