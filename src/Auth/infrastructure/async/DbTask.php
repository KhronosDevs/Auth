<?php

declare(strict_types=1);

namespace Auth\infrastructure\async;

use Auth\infrastructure\storage\sqlite\SqliteExecutor;
use pocketmine\adapter\driven\threading\PluginTask;

/**
 * One serialized SQLite job, executed on a pool worker thread.
 *
 * Requests/responses cross the thread boundary as JSON strings (scalars
 * only, per the PluginTask contract). Exactly ONE of these is in flight at
 * any time (enforced by JobQueue) so SQLite never sees concurrent access.
 */
final class DbTask extends PluginTask {
	/** JSON: {op, path, ...params} */
	public string $request = '';
	/** JSON response written by the worker; read on the main thread. */
	public string $response = '';
	/** Non-empty when the operation failed (exceptions cannot cross pmmpthread). */
	public string $error = '';

	public function run(): void {
		try {
			$request = json_decode($this->request, true);
			if (!is_array($request)) {
				throw new \InvalidArgumentException('Malformed DB request');
			}
			$result = SqliteExecutor::execute($request);
			$this->response = json_encode($result) ?: '{}';
			$this->complete($result);
		} catch (\Throwable $e) {
			// Exceptions CANNOT cross pmmpthread boundaries (FutureImpl::$error
			// is a ThreadSafe property; assigning one fatals the worker) - so
			// errors travel back as plain strings and the main thread raises.
			$this->error = $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine();
			$this->complete(null);
		}
	}
}
