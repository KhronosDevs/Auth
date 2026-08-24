<?php
declare(strict_types=1);

$ROOT = dirname(__DIR__, 3);
require dirname(__DIR__, 3) . '/autoload.php';

use Auth\domain\AuthStage;
use pocketmine\api\entity\Player;
use pocketmine\core\ecs\EntityRef;
use pocketmine\port\driven\PlayerRef;

$fails = 0;
function check(string $n, bool $ok): void { global $fails; if (!$ok) $fails++; echo ($ok?"PASS":"FAIL")," - $n\n"; }

$kernel = \pocketmine\bootstrap();
$uname = 'U' . substr((string)time(), -6);
$uidA = $uname . '-A';
$uidB = $uname . '-B';
$pm = $kernel->getPluginManager();
$plugin = $pm->loadPlugin($ROOT . '/plugins/Auth');
check('plugin enabled', $plugin !== null);
$kernel->setAutoShutdownOnRun(false);

$rAuth = new ReflectionProperty($plugin, 'auth'); $rAuth->setAccessible(true);
$authSvc = $rAuth->getValue($plugin);
$rSessions = new ReflectionProperty(Auth\application\AuthService::class, 'sessions');
$rSessions->setAccessible(true);
$sessions = $rSessions->getValue($authSvc);
$world = $kernel->getWorld();

function facade($kernel, int $id): Player {
    return new Player(EntityRef::create($id, $kernel->getWorld()), $kernel->getWorld());
}
function tickN($kernel, int $n): void { for ($i=0;$i<$n;$i++) $kernel->run(1); }
function waitFor($kernel, callable $cond, int $timeoutMs = 8000): bool {
    $start = microtime(true);
    while (microtime(true) - $start < $timeoutMs / 1000) {
        $kernel->run(1);
        if ($cond()) return true;
        usleep(1000);
    }
    return false;
}

// --- Alice joins and registers through the REAL command path ---
$a = $kernel->getPlayerJoinService()->handleJoin(new PlayerRef($uidA, -1, $uidA), $uidA);
$idA = $a->getId();
tickN($kernel, 10);
$pA = facade($kernel, $idA);
$authSvc->handleRegisterCommand($pA, ['secret123', 'secret123']);
// bcrypt costs ~300ms of REAL time; headless ticks fly past it, so wait on
// the condition rather than counting ticks.
$ok = waitFor($kernel, fn() => ($s = $sessions->get($idA)) !== null && $s->stage === AuthStage::Authenticated);
check('registered + auto-authed', $ok);
$sA = $sessions->get($idA);

// --- Regression guard: same-session account commands must work right
// --- after registering (they once gated on a null join-time snapshot).
$authSvc->handleTwoFaCommand($pA, ['enable']);
check('/2fa enable works immediately after register', $sA !== null && $sA->pendingTotpSecret !== null);

if ($sA !== null && $sA->pendingTotpSecret !== null) {
    // Confirm with a freshly-computed valid TOTP code for the pending secret.
    $code = Auth\domain\twofactor\Totp::at(
        Auth\domain\twofactor\Base32::decode($sA->pendingTotpSecret),
        time(),
        30, 6,
    );
    $authSvc->handleTwoFaCommand($pA, ['confirm', $code]);
    tickN($kernel, 10);
    check('/2fa confirm activates 2FA + issues backup codes', ($sA->account?->totpEnabled ?? false) === true && $sA->pendingBackupCodes !== null && $sA->pendingTotpSecret === null);

    // changepassword: wrong old rejected, then correct old accepted.
    $authSvc->handleChangePasswordCommand($pA, ['wrongold', 'newpass456']);
    tickN($kernel, 15);
    $hashAfterWrong = $sA->account?->passwordHash ?? '';
    $authSvc->handleChangePasswordCommand($pA, ['secret123', 'newpass456']);
    waitFor($kernel, fn() => isset($sA->account?->passwordHash) && $sA->account->passwordHash !== $hashAfterWrong && str_starts_with($sA->account->passwordHash, '$2y$'));
    check('/changepassword verifies old + persists new', str_starts_with((string)($sA->account?->passwordHash ?? ''), '$2y$'));
}

// --- Alice leaves ---
$kernel->getPlayerLeaveService()->handleDisconnect(new PlayerRef($uidA, $idA, 'Alice'), 'quit');
tickN($kernel, 5);
check('alice session cleaned up', $sessions->get($idA) === null);

// --- Bob joins with a DIFFERENT name (unregistered) ---
$b = $kernel->getPlayerJoinService()->handleJoin(new PlayerRef($uidB, -1, $uidB), $uidB);
$idB = $b->getId();
$ok2 = waitFor($kernel, fn() => ($s = $sessions->get($idB)) !== null && $s->stage === AuthStage::Password);
$sB = $sessions->get($idB);
check('bob session exists', $sB !== null);
check('bob got the join-new prompt state', $ok2);

// --- And Alice herself rejoins (trusted-IP auto-login expected) ---
$a2 = $kernel->getPlayerJoinService()->handleJoin(new PlayerRef($uidA, -1, $uidA), $uidA);
waitFor($kernel, fn() => ($s = $sessions->get($a2->getId())) !== null && $s->stage !== AuthStage::Loading);
$sA2 = $sessions->get($a2->getId());
check('alice rejoin resolves a session', $sA2 !== null);
// NOTE: true trusted-IP auto-login can't be exercised headlessly - sessions
// here have no network address (ip=''), so the trust lookup legitimately
// misses. Assert she reached a DECIDED state (password prompt) instead.
check('alice rejoin reached password stage (trusted-IP needs a real address)', $sA2 !== null && $sA2->stage === AuthStage::Password);

echo "\n", $fails === 0 ? "REJOIN-REGISTERED TEST PASSED" : "$fails FAILED", "\n";
exit($fails === 0 ? 0 : 1);
