<?php

declare(strict_types=1);

namespace Auth\infrastructure\async;

use Auth\application\port\PasswordEncoder;
use Auth\domain\password\PasswordPolicy;
use pocketmine\adapter\driven\threading\PluginFuture;
use pocketmine\adapter\driven\threading\PluginTask;
use pocketmine\api\scheduler\Scheduler;
use pocketmine\port\driven\ThreadingPort;

/**
 * Main-thread job dispatcher.
 *
 * DB jobs: strict FIFO with AT MOST ONE DbTask in flight. This is what
 * keeps SQLite single-threaded (see SqliteExecutor). The in-flight flag is
 * only ever cleared inside the completion handler (main thread), so
 * ordering guarantees hold without locks. Implements the application's
 * PasswordEncoder port; hashing runs on pool workers.
 *
 * COMPLETION DELIVERY: we deliberately do NOT use PluginFuture::then().
 * The kernel loses track of futures submitted from inside a completion
 * callback (Kernel::drainPluginFutures replaces pendingPluginFutures with
 * its $remaining list after iterating - API gap 2c), so then()-callbacks of
 * CHAINED jobs would never fire. Instead every future we submit is polled
 * by our own per-tick sweep (drain), which invokes the handlers directly.
 * One empty-array check per tick when idle; O(pending) otherwise.
 */
final class JobQueue implements PasswordEncoder {
	/**
	 * All SQLite work is PINNED to this pool worker (API gap 3 fix:
	 * submitPluginTaskToWorker). Combined with SqliteExecutor's per-thread
	 * connection cache this gives exactly ONE warm PDO connection serving
	 * every query - zero reconnect cost, single-writer by construction.
	 * Hash/verify tasks stay on the round-robin pool (CPU-bound, parallel).
	 */
	private const DB_WORKER_ID = 0;

	/** @var list<array{array<string,mixed>, callable(array): void}> */
	private array $dbQueue = [];
	private bool $dbInFlight = false;

	/** @var list<array{PluginFuture, PluginTask, callable(mixed): void, ?callable(\Throwable): void}> */
	private array $inflight = [];

	public function __construct(
		private readonly ThreadingPort $threading,
		private readonly PasswordPolicy $policy,
		private readonly bool $debug = false,
		?Scheduler $scheduler = null,
	) {
		if ($scheduler !== null) {
			$scheduler->scheduleRepeatingTask(function (): void {
				$this->drain();
			}, 1);
		}
	}

	// ---- PasswordEncoder port -------------------------------------------

	public function hash(string $password, callable $onDone): void {
		$task = new HashTask();
		$task->mode = HashTask::MODE_HASH;
		$task->password = $password;
		$this->applyPolicy($task);
		$this->submit($task,
			function (HashTask $t) use ($onDone): void {
				if ($t->error !== '') {
					error_log('[Auth] Hash task failed: ' . $t->error);
					return;
				}
				$onDone($t->result);
			},
			function (\Throwable $e): void {
				error_log('[Auth] Hash task failed: ' . $e->getMessage());
			},
		);
	}

	public function verify(string $password, string $hash, callable $onDone): void {
		$task = new HashTask();
		$task->mode = HashTask::MODE_VERIFY;
		$task->password = $password;
		$task->hash = $hash;
		$this->applyPolicy($task);
		$this->submit($task,
			function (HashTask $t) use ($onDone): void {
				if ($t->error !== '') {
					error_log('[Auth] Verify task failed: ' . $t->error);
					return;
				}
				$onDone($t->result === '1');
			},
			function (\Throwable $e): void {
				error_log('[Auth] Verify task failed: ' . $e->getMessage());
			},
		);
	}

	// ---- DB queue ---------------------------------------------------------

	/**
	 * Enqueue a SQLite operation. $request must contain 'op' and 'path'.
	 * The callback receives the decoded response array on the main thread.
	 *
	 * @param array<string, mixed> $request
	 * @param callable(array): void $onResult
	 */
	public function db(array $request, ?callable $onResult = null): void {
		$this->dbQueue[] = [$request, $onResult ?? static function (array $_): void {}];
		$this->pumpDb();
	}

	private function pumpDb(): void {
		if ($this->dbInFlight || $this->dbQueue === []) {
			return;
		}
		[$request, $onResult] = array_shift($this->dbQueue);
		$this->dbInFlight = true;

		$this->dbg('submitting op=' . ($request['op'] ?? '?') . ' queued=' . count($this->dbQueue));
		$task = new DbTask();
		$task->request = json_encode($request) ?: '{}';
		$this->submitPinned($task,
			function (DbTask $t) use ($onResult): void {
				$this->dbInFlight = false;
				if ($t->error !== '') {
					error_log('[Auth] DB task failed: ' . $t->error);
					$this->pumpDb();
					return;
				}
				try {
					$response = json_decode($t->response, true);
					if (is_array($response)) {
						$onResult($response);
					}
				} catch (\Throwable $e) {
					// Never let one bad response stall the queue - but never
					// hide it either.
					error_log('[Auth] DB result handler failed: ' . $e->getMessage());
				}
				$this->pumpDb();
			},
			function (\Throwable $e): void {
				$this->dbg('FAILED: ' . $e->getMessage());
				$this->dbInFlight = false;
				error_log('[Auth] DB task failed: ' . $e->getMessage());
				$this->pumpDb();
			},
		);
	}

	// ---- completion plumbing ----------------------------------------------

	/**
	 * Submit a task and register its handlers. Handlers fire on the main
	 * thread from drain() - never from PluginFuture::then(), see class doc.
	 */
	private function submit(PluginTask $task, callable $onSuccess, ?callable $onError): void {
		$future = $this->threading->submitPluginTask($task);
		$this->inflight[] = [$future, $task, $onSuccess, $onError];
	}

	/** True once the pool has spawned worker 0 (pmmpthread spawns lazily). */
	private bool $dbWorkerReady = false;
	/** Set if pinned submission proved impossible - degrade to round-robin. */
	private bool $pinUnavailable = false;
	/** @var list<array{PluginTask, callable(mixed): void, ?callable(\Throwable): void}> */
	private array $pinnedPending = [];

	private function submitPinned(PluginTask $task, callable $onSuccess, ?callable $onError): void {
		if ($this->dbWorkerReady && !$this->pinUnavailable) {
			$future = $this->threading->submitPluginTaskToWorker(self::DB_WORKER_ID, $task);
			$this->inflight[] = [$future, $task, $onSuccess, $onError];
			return;
		}
		if ($this->pinUnavailable) {
			$this->submit($task, $onSuccess, $onError); // graceful degradation
			return;
		}
		// Worker 0 not spawned yet: stash and send a throwaway round-robin
		// task to force the pool to spawn it, then flush.
		$this->pinnedPending[] = [$task, $onSuccess, $onError];
		$this->warmDbWorker();
	}

	private bool $warming = false;

	private function warmDbWorker(): void {
		if ($this->warming || $this->dbWorkerReady) {
			return;
		}
		$this->warming = true;
		$warm = new HashTask(); // instant no-op verify; spawns pool worker 0
		$future = $this->threading->submitPluginTask($warm);
		$this->inflight[] = [$future, $warm,
			function (): void {
				$this->warming = false;
				$this->dbWorkerReady = true;
				foreach ($this->pinnedPending as [$t, $ok, $err]) {
					$this->submitPinned($t, $ok, $err);
				}
				$this->pinnedPending = [];
			},
			function (\Throwable $e): void {
				// Warming failed - never strand queued work.
				$this->warming = false;
				$this->pinUnavailable = true;
				error_log('[Auth] DB worker pinning unavailable, falling back to round-robin: ' . $e->getMessage());
				foreach ($this->pinnedPending as [$t, $ok, $err]) {
					$this->submit($t, $ok, $err);
				}
				$this->pinnedPending = [];
			},
		];
	}

	private function drain(): void {
		if ($this->inflight === []) {
			return; // hot path: single empty-check per tick
		}
		foreach ($this->inflight as $k => [$future, $task, $onSuccess, $onError]) {
			if (!$future->isDone()) {
				continue;
			}
			unset($this->inflight[$k]);
			if ($future->isCancelled()) {
				continue;
			}
			try {
				$onSuccess($task);
			} catch (\Throwable $e) {
				if ($onError !== null) {
					$onError($e);
				} else {
					error_log('[Auth] async job handler failed: ' . $e->getMessage());
				}
			}
		}
	}

	/** True while a SQLite job executes or queued jobs remain. */
	public function hasPendingDbWork(): bool {
		return $this->dbInFlight || $this->dbQueue !== [];
	}

	private function applyPolicy(HashTask $task): void {
		$task->algo = $this->policy->algorithm;
		$task->bcryptCost = $this->policy->bcryptCost;
		$task->argonMemoryKib = $this->policy->argonMemoryKib;
		$task->argonTimeCost = $this->policy->argonTimeCost;
		$task->argonThreads = $this->policy->argonThreads;
	}

	private function dbg(string $m): void {
		if ($this->debug) {
			error_log('[Auth][trace][queue] ' . $m);
		}
	}
}
