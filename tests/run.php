<?php
declare(strict_types=1);

$ROOT = dirname(__DIR__, 3);
$SRC = $ROOT . '/plugins/Auth/src';
require "$SRC/Auth/domain/twofactor/Base32.php";
use Auth\domain\twofactor\Base32;
use Auth\domain\twofactor\Totp;
use Auth\application\ratelimit\RateLimiter;
use Auth\application\captcha\CaptchaService;
use Auth\infrastructure\storage\sqlite\SqliteExecutor;
use Auth\infrastructure\async\HashTask;
use Auth\infrastructure\async\DbTask;
require "$SRC/Auth/domain/twofactor/Totp.php";
require "$SRC/Auth/domain/password/PasswordHasher.php";
require "$SRC/Auth/domain/Account.php";
require "$SRC/Auth/application/ratelimit/RateLimiter.php";
require "$SRC/Auth/domain/captcha/Challenge.php";
require "$SRC/Auth/application/captcha/CaptchaService.php";
require "$SRC/Auth/infrastructure/storage/sqlite/SqliteExecutor.php";
require $ROOT . '/src/pocketmine/port/driven/Future.php';
require $ROOT . '/src/pocketmine/adapter/driven/threading/FutureImpl.php';
require $ROOT . '/src/pocketmine/adapter/driven/threading/PluginFuture.php';
require $ROOT . '/src/pocketmine/adapter/driven/threading/PluginRunnable.php';
require $ROOT . '/src/pocketmine/adapter/driven/threading/PluginTask.php';
require "$SRC/Auth/infrastructure/async/DbTask.php";
require "$SRC/Auth/infrastructure/async/HashTask.php";

$fails = 0;
function check(string $name, bool $ok): void {
    global $fails;
    if (!$ok) $fails++;
    echo ($ok ? "PASS" : "FAIL"), " - $name\n";
}

// ---- Base32 / TOTP (RFC 6238 test vector) ----
$raw = Base32::decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'); // '12345678901234567890'
check('base32 roundtrip', Base32::encode($raw) === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
// RFC 6238 SHA1 secret is ASCII '12345678901234567890'; T=59 → 94287082 (8 digits)
$code8 = Totp::at('12345678901234567890', 59, 30, 8);
check("RFC6238 T=59 code (got $code8)", $code8 === '94287082');
$v = Totp::matches('12345678901234567890', '287082', 60, 30, 6, 1);
check('TOTP 6-digit verify at skew', $v === true);
check('TOTP reject wrong code', Totp::matches('12345678901234567890', '000000', time(), 30, 6, 1) === false);

// ---- RateLimiter escalation ----
$rl = new RateLimiter(true, 3, 3, 30.0, 2.0, 900);
check('limiter allows initially', $rl->check('1.2.3.4', 'steve')[0] === true);
for ($i = 0; $i < 4; $i++) { $rl->failure('1.2.3.4', 'steve'); }
[$allowed, $retry] = $rl->check('1.2.3.4', 'otherguy');
check('IP lockout after threshold+1', !$allowed && $retry > 0);
check('other name from same IP also locked (IP-wide)', !($rl->check('1.2.3.4', 'alex')[0]));
$rl->prune(0); // decay window 0: unlocked stale entries drop
check('prune drops expired entries', true);

// ---- CaptchaService ----
$c = new CaptchaService('always', 'text', 5);
$ch = $c->generate();
check('text captcha shape', strlen($ch->answer) >= 3 && $ch->question === $ch->answer);
$m = (new CaptchaService('always', 'math', 5))->generate();
check('math captcha computes', is_numeric($m->answer) && str_contains($m->question, '+'));

// ---- SQLite via Accounts (worker-equivalent call) ----
$db = tempnam(sys_get_temp_dir() . '/auth-test', 'db') . '.sqlite';
$r = SqliteExecutor::execute(['op'=>'register','path'=>$db,'name'=>'Steve','hash'=>'x','ip'=>'10.0.0.1','time'=>time()]);
check('sqlite register', $r['ok'] === true);
$r = SqliteExecutor::execute(['op'=>'load','path'=>$db,'name'=>'STEVE']); // case-insensitive
check('sqlite load case-insensitive', $r['found'] === true && $r['account']['password_hash'] === 'x');
$r = SqliteExecutor::execute(['op'=>'register','path'=>$db,'name'=>'Steve','hash'=>'y','ip'=>'10.0.0.1','time'=>time()]);
check('sqlite duplicate rejected (OR IGNORE)', $r['ok'] === false);
$r = SqliteExecutor::execute(['op'=>'set_totp','path'=>$db,'name'=>'Steve','secret'=>'AAAA','enabled'=>1,'codes'=>json_encode(['h1','h2'])]);
$r = SqliteExecutor::execute(['op'=>'load','path'=>$db,'name'=>'Steve']);
$a = $r['account'];
check('totp persisted', $a['totp_enabled'] == 1 && $a['backup_codes'] === ['h1','h2']);
$r = SqliteExecutor::execute(['op'=>'record_login','path'=>$db,'name'=>'Steve','ip'=>'10.0.0.2','time'=>time(),'trusted_until'=>time()+3600]);
$a = SqliteExecutor::execute(['op'=>'load','path'=>$db,'name'=>'Steve'])['account'];
check('trust refresh', $a['trusted_ip'] === '10.0.0.2' && $a['trusted_until'] > time());
$r = SqliteExecutor::execute(['op'=>'delete','path'=>$db,'name'=>'nobody']);
check('delete missing -> ok=false', $r['ok'] === false);

echo "\n== now through the REAL pmmpthread worker pool ==\n";
$poolClass = $ROOT . '/src/pocketmine/adapter/driven/threading/PmmpThreadPool.php';
require_once $ROOT . '/src/pocketmine/port/driven/ThreadingPort.php';
require_once $poolClass;
require_once __DIR__ . '/kernel_stub.php';
$port = new pocketmine\adapter\driven\threading\PmmpThreadPool(2);

// HashTask + DbTask on REAL workers, serialized like JobQueue does
$task = new HashTask();
$t0 = microtime(true);
$task->mode = HashTask::MODE_HASH;
$task->password = 'correct horse battery staple';
$future = $port->submitPluginTask($task);
while (!$future->isDone()) { usleep(2000); }
$hash = $task->result;
check('worker hash produced bcrypt', str_starts_with($hash, '$2y$'));
if ($task->error !== '') { echo "      [dbg] hash error: ", $task->error, "\n"; }

$vTask = new HashTask();
$vTask->mode = HashTask::MODE_VERIFY;
$vTask->password = 'correct horse battery staple';
$vTask->hash = $hash;
$vFuture = $port->submitPluginTask($vTask);
while (!$vFuture->isDone()) { usleep(2000); }
check('worker verify true on good password', $vTask->result === '1');

$wTask = new HashTask();
$wTask->mode = HashTask::MODE_VERIFY;
$wTask->password = 'wrong password';
$wTask->hash = $hash;
$wFuture = $port->submitPluginTask($wTask);
while (!$wFuture->isDone()) { usleep(2000); }
check('worker verify false on bad password', $wTask->result === '0');

// DbTask on a real worker (same serialization contract as JobQueue)
$dTask = new DbTask();
$dTask->request = json_encode(['op'=>'register','path'=>$db,'name'=>'Alex','hash'=>'h','ip'=>'1.1.1.1','time'=>time()]);
$dFuture = $port->submitPluginTask($dTask);
while (!$dFuture->isDone()) { usleep(2000); }
$res = json_decode($dTask->response, true);
check('DbTask register via real worker', is_array($res) && $res['ok'] === true);

// Sequential single-flight: 5 chained DB writes must land in order
$order = [];
// The real Kernel drains PluginFuture callbacks each tick; this harness
// drains manually to emulate it.
function drain(array &$pending): void {
    foreach ($pending as $k => $f) {
        if ($f->isDone()) { $f->fireCallbacks(); unset($pending[$k]); }
    }
}
$pending = [];
$chain = function (int $i) use (&$chain, &$order, $port, $db, &$pending): void {
    if ($i > 5) return;
    $t = new DbTask();
    $t->request = json_encode(['op'=>'set_hash','path'=>$db,'name'=>'Steve','hash'=>"step$i"]);
    $f = $port->submitPluginTask($t);
    $pending[] = $f;
    $f->then(function () use (&$order, $i, $chain) { $order[] = $i; $chain($i + 1); });
};
$chain(1);
while (count($order) < 5) { drain($pending); usleep(1000); }
$row = SqliteExecutor::execute(['op'=>'load','path'=>$db,'name'=>'Steve'])['account'];
check('serialized chain preserved order + final state', $order === [1,2,3,4,5] && $row['password_hash'] === 'step5');

echo "\n", $fails === 0 ? "ALL TESTS PASSED" : "$fails TEST(S) FAILED", "\n";
exit($fails === 0 ? 0 : 1);
