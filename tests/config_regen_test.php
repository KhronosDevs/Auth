<?php
declare(strict_types=1);

$ROOT = dirname(__DIR__, 3);
require __DIR__ . '/../src/Auth/config/AuthConfig.php';
require $ROOT . '/src/pocketmine/api/plugin/Config.php';

use Auth\config\AuthConfig;

$fails = 0;
function check(string $name, bool $ok): void {
	global $fails;
	if (!$ok) $fails++;
	echo ($ok ? "PASS" : "FAIL"), " - $name\n";
}

$dir = sys_get_temp_dir() . '/auth-cfg-test-' . mt_rand();
mkdir($dir, 0775, true);

$cfg = AuthConfig::load($dir);
check('config.yml materialized', is_file("$dir/config.yml"));
check('join-registered present in file', strpos((string) file_get_contents("$dir/config.yml"), 'join-registered') !== false);
check('msg() resolves join-new in-memory', $cfg->msg('join-new') !== '');
check('msg() resolves prefix in-memory', $cfg->msg('prefix') !== '');

$cfg2 = AuthConfig::load($dir);
check('msg() resolves from file on reload', $cfg2->msg('join-new') !== '');

// User edits must survive: write a customized message, reload, verify merge.
$file = "$dir/config.yml";
$content = file_get_contents($file);
file_put_contents($file, str_replace('Welcome! Register', 'CUSTOM REGISTER', $content));
$cfg3 = AuthConfig::load($dir);
check('user edit merged on reload', strpos($cfg3->msg('join-new'), 'CUSTOM REGISTER') !== false);

echo "\n", $fails === 0 ? "CONFIG REGEN TEST PASSED" : "$fails CHECK(S) FAILED", "\n";
exit($fails === 0 ? 0 : 1);
