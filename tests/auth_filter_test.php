<?php
declare(strict_types=1);

$ROOT = dirname(__DIR__, 3);
require $ROOT . '/autoload.php';
 
require $ROOT . '/plugins/Auth/src/Auth/application/session/AuthSession.php';
require $ROOT . '/plugins/Auth/src/Auth/application/session/SessionManager.php';
require $ROOT . '/plugins/Auth/src/Auth/domain/AuthStage.php';
require $ROOT . '/plugins/Auth/src/Auth/infrastructure/player/VisibilityFilter.php';

use pocketmine\core\ecs\EntityRef;
use pocketmine\port\driven\PlayerRef;
use Auth\application\session\SessionManager;
use Auth\domain\AuthStage;
use Auth\infrastructure\player\VisibilityFilter;

$kernel = \pocketmine\bootstrap();
$world = $kernel->getWorld();

$sessions = new SessionManager();
$filter = new VisibilityFilter($sessions);

// Two players join through the real service.
$j = $kernel->getPlayerJoinService();
$a = $j->handleJoin(new PlayerRef('aaaa-1', -1, 'Alice'), 'Alice');
$b = $j->handleJoin(new PlayerRef('bbbb-1', -1, 'Bob'), 'Bob');

// Register them in OUR session map (in production Main passes the same
// instance to both AuthService and the filter).
$sA = $sessions->create($a->getId(), 'Alice', 'aaaa-1', '10.0.0.1',
    new PlayerRef('aaaa-1', $a->getId(), 'Alice'));
$sB = $sessions->create($b->getId(), 'Bob', 'bbbb-1', '10.0.0.2',
    new PlayerRef('bbbb-1', $b->getId(), 'Bob'));

// What broadcastEntityStates actually passes: PlayerRef + raw ecs Entity.
$entityA = $world->getEntities()[$a->getId()];
$viewerB = new PlayerRef('bbbb-1', $b->getId(), 'Bob');

$r = $filter($viewerB, $entityA); // unauthed Bob viewing unauthed Alice
echo "unauthed->unauthed suppressed: ", $r === false ? "PASS" : "FAIL", "\n";

// Mob entity: must stay visible even to unauthed viewers.
$mob = $world->spawn((new pocketmine\core\ecs\EntityBuilder())
    ->at(5, 64, 5)
    ->with(new pocketmine\core\component\HealthComponent(20, 20))
    ->with(new pocketmine\core\component\MetadataComponent(['entityType' => 'Zombie'])));
$r2 = $filter($viewerB, $world->getEntities()[$mob->getId()]);
echo "mob visible to unauthed viewer: ", $r2 === true ? "PASS" : "FAIL", "\n";

// After Bob authenticates, Alice becomes visible to him.
$sessions->markAuthenticated($sB);
$r3 = $filter(new PlayerRef('bbbb-1', $b->getId(), 'Bob'), $entityA);
echo "authed viewer sees unauthed player: ", $r3 === true ? "PASS" : "FAIL", "\n";
