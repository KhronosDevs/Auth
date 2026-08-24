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
$pm = $kernel->getPluginManager();
$plugin = $pm->loadPlugin($ROOT . '/plugins/Auth');
$kernel->setAutoShutdownOnRun(false);
check('plugin enabled', $plugin !== null);

$rAuth = new ReflectionProperty($plugin, 'auth'); $rAuth->setAccessible(true);
$authSvc = $rAuth->getValue($plugin);
$rSessions = new ReflectionProperty(Auth\application\AuthService::class, 'sessions');
$rSessions->setAccessible(true);
$sessions = $rSessions->getValue($authSvc);

function facade($kernel, int $id): Player { return new Player(EntityRef::create($id, $kernel->getWorld()), $kernel->getWorld()); }
function tickN($kernel, int $n): void { for ($i=0;$i<$n;$i++) $kernel->run(1); }
function waitFor($kernel, callable $cond, int $timeoutMs = 8000): bool {
    $t = microtime(true);
    while (microtime(true) - $t < $timeoutMs / 1000) { $kernel->run(1); if ($cond()) return true; usleep(1000); }
    return false;
}

$name = 'L' . substr((string)time(), -6);

// ---- Session 1: register -> 2FA -> changepassword ----
$e1 = $kernel->getPlayerJoinService()->handleJoin(new PlayerRef($name, -1, $name), $name);
waitFor($kernel, fn() => ($s = $sessions->get($e1->getId())) !== null && $s->stage === AuthStage::Password);
$p = facade($kernel, $e1->getId());
$s1 = $sessions->get($e1->getId());

$authSvc->handleRegisterCommand($p, ['firstpass', 'firstpass']);
waitFor($kernel, fn() => $s1->stage === AuthStage::Authenticated);
check('S1: registered + authed', true);

$authSvc->handleTwoFaCommand($p, ['enable']);
tickN($kernel, 2);
$secret = $s1->pendingTotpSecret ?? '';
$code = $secret !== '' ? Auth\domain\twofactor\Totp::at(Auth\domain\twofactor\Base32::decode($secret), time(), 30, 6) : '';
$authSvc->handleTwoFaCommand($p, ['confirm', $code]);
tickN($kernel, 10);
check('S1: 2FA confirmed', (($s1->account?->totpEnabled ?? false) === true));

$hashBefore = $s1->account?->passwordHash;
$authSvc->handleChangePasswordCommand($p, ['firstpass', 'secondpass']);
// Block until the SET_HASH completion callback has refreshed the snapshot -
// otherwise session 2's async load can race ahead of the write.
$t0 = microtime(true);
$settled = waitFor($kernel, fn() => $s1->account !== null && $s1->account->passwordHash !== $hashBefore);
error_log('[probe] changepw settled=' . var_export($settled, true) . ' after ' . round((microtime(true)-$t0)*1000) . 'ms');
check('S1: changepassword accepted', $settled);
echo "      [dbg] reg-hash=", substr($hashBefore,0,12), "  new-hash=", substr($s1->account->passwordHash,0,12), "\n";

$kernel->getPlayerLeaveService()->handleDisconnect(new PlayerRef($name, $e1->getId(), $name), 'quit');
tickN($kernel, 5);

// ---- Session 2: /login flows ----
$e2 = $kernel->getPlayerJoinService()->handleJoin(new PlayerRef($name.'x', -1, $name), $name);
$id2 = $e2->getId();
waitFor($kernel, fn() => ($s = $sessions->get($id2)) !== null && $s->stage === AuthStage::Password);
$p2 = facade($kernel, $id2);
$s2 = $sessions->get($id2);
check('S2: join prompt state reached', $s2 !== null && $s2->stage === AuthStage::Password);

echo "      [dbg] s2-loaded-hash=", substr((string)($s2->account?->passwordHash ?? 'NULL'),0,12), "\n";
// Wrong password
$authSvc->handleLoginCommand($p2, ['totally-wrong']);
waitFor($kernel, fn() => $s2->failedLogins >= 1);
check('S2: /login wrong password rejected', $s2->failedLogins >= 1 && $s2->stage === AuthStage::Password);

// OLD password (pre-changepassword) must also fail
$authSvc->handleLoginCommand($p2, ['firstpass']);
waitFor($kernel, fn() => $s2->failedLogins >= 2 || $s2->stage !== AuthStage::Password);
error_log('[probe] after old-pw: fails=' . $s2->failedLogins . ' stage=' . $s2->stage->name);
check('S2: /login OLD password (pre-change) rejected', $s2->failedLogins >= 2 && $s2->stage === AuthStage::Password);

// NEW password -> should advance to the 2FA stage
$authSvc->handleLoginCommand($p2, ['secondpass']);
waitFor($kernel, fn() => $s2->stage !== AuthStage::Password);
error_log('[probe] after new-pw: stage=' . $s2->stage->name);
check('S2: /login NEW password accepted -> 2FA stage', $s2->stage === AuthStage::TwoFactor);

// Correct TOTP -> authed
$rowSecret = (string)($s2->account?->totpSecret ?? '');
$totp = Auth\domain\twofactor\Totp::at(Auth\domain\twofactor\Base32::decode($rowSecret), time(), 30, 6);
$authSvc->handleTwoFaCommand($p2, [$totp]);
check('S2: valid TOTP completes login', $s2->stage === AuthStage::Authenticated);

echo "\n", $fails === 0 ? "LOGIN FLOW TEST PASSED" : "$fails FAILED", "\n";
exit($fails === 0 ? 0 : 1);
