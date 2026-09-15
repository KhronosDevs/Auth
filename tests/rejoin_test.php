<?php

declare(strict_types=1);

$ROOT = dirname(__DIR__, 3);

require dirname(__DIR__, 3) . '/autoload.php';

use pocketmine\port\driven\PlayerRef;

$fails = 0;
function check(string $n, bool $ok): void { global $fails; if (!$ok) $fails++; echo ($ok ? "PASS" : "FAIL"), " - $n\n"; }

$kernel = \pocketmine\bootstrap();
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
check('plugin enabled', $plugin !== null);
$kernel->setAutoShutdownOnRun(false);

$joinService = $kernel->getPlayerJoinService();

// Reach internals for verification.
$rAuth = new ReflectionProperty($plugin, 'auth');
$rAuth->setAccessible(true);
$authSvc = $rAuth->getValue($plugin);
$rSessions = new ReflectionProperty(Auth\application\AuthService::class, 'sessions');
$rSessions->setAccessible(true);
$sessions = $rSessions->getValue($authSvc);

function waitFor($kernel, callable $cond, int $timeoutMs = 8000): bool {
	$start = microtime(true);
	while (microtime(true) - $start < $timeoutMs / 1000) {
		$kernel->run(1);
		if ($cond()) {
			return true;
		}
		usleep(1000);
	}
	return false;
}

$uname = 'U' . substr((string)time(), -6);

// --- First player joins (fresh name -> registration prompt stage) ---
$a = $joinService->handleJoin(new PlayerRef($uname . '-a', -1, $uname . 'A'), $uname . 'A');
$idA = $a->getId();
echo "      alice entity id: $idA\n";
waitFor($kernel, fn() => ($s = $sessions->get($idA)) !== null && $s->stage === Auth\domain\AuthStage::Password);
$sA = $sessions->get($idA);
check('alice session reached password stage', $sA !== null && $sA->stage === Auth\domain\AuthStage::Password);

// --- Alice leaves ---
$kernel->getPlayerLeaveService()->handleDisconnect(new PlayerRef($uname . '-a', $idA, $uname . 'A'), 'test quit');
waitFor($kernel, fn() => $sessions->get($idA) === null);
check('alice session removed on quit', $sessions->get($idA) === null);

// --- Bob joins with a different name ---
$b = $joinService->handleJoin(new PlayerRef($uname . '-b', -1, $uname . 'B'), $uname . 'B');
$idB = $b->getId();
echo "      bob entity id: $idB\n";
waitFor($kernel, fn() => ($s = $sessions->get($idB)) !== null && $s->stage === Auth\domain\AuthStage::Password);
$sB = $sessions->get($idB);
check('bob session exists', $sB !== null);
echo "      bob stage: ", $sB?->stage?->name ?? 'GONE', "\n";
check('bob session reached password stage (got prompt)', $sB !== null && $sB->stage === Auth\domain\AuthStage::Password);

echo "\n", $fails === 0 ? "REJOIN TEST PASSED" : "$fails FAILED", "\n";
exit($fails === 0 ? 0 : 1);
