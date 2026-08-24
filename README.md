# Auth (Khronos plugin)

Registration, login, TOTP two-factor authentication, chat captcha and
brute-force protection for Khronos (MCPE 0.15.10, protocol 84, API 2.0.0).

## Setup

1. This directory *is* the plugin: drop/symlink it into the server's
   `plugins/` folder (`plugin.yml` + `src/` + `config.yml`).
2. Start the server. On first login players use:

```
/register <password> <confirmPassword>     create an account + auto-login
/login <password>                          log in to an existing account
/captcha <code>                            answer a captcha challenge (when prompted)
/changepassword <old> <new>                change password (must be authenticated)
/2fa <code>                                submit a 2FA code at login
/2fa enable                                start 2FA enrollment (shows secret + otpauth:// URI)
/2fa confirm <code>                        verify enrollment, receive backup codes
/2fa disable <password>                    turn 2FA off (password required)
/authadmin unregister|resetpw|codes ...    admin commands (auth.admin permission, default op)
```

All account data lives in `storage.sqlite-file` (default `accounts.sqlite`)
inside this folder. Delete it to wipe all accounts.

## Commands

### Player commands (usable in-game)

| Command | When | Description |
|---|---|---|
| `/register <password> <confirmPassword>` | before auth, new name | Create an account; auto-logs you in |
| `/login <password>` (`/log`) | before auth, registered name | Log in |
| `/captcha <code>` | when prompted | Answer your captcha challenge |
| `/2fa <code>` | at the 2FA step | Submit a TOTP code or a single-use backup code |
| `/2fa enable` | authenticated | Start enrollment — prints secret + `otpauth://` URI |
| `/2fa confirm <code>` | after `/2fa enable` | Verify the secret; prints single-use backup codes once |
| `/2fa disable <password>` | authenticated | Removes 2FA (requires current password) |
| `/changepassword <old> <new>` (`/changepw`) | authenticated | Change your password |

### Admin commands (`auth.admin`, default: op; console allowed)

| Command | Description |
|---|---|
| `/authadmin unregister <player>` | Delete an account (works offline); kicks online targets |
| `/authadmin resetpw <player> <newPassword>` | Force-set a password (works offline); kicks online targets |
| `/authadmin codes <player>` | Regenerate single-use backup codes, printed to the admin |

While unauthenticated, **all other server commands are blocked** — only
`/register`, `/login` and `/captcha` get through.

## Player flows

### Login flow (registered player)

```
join ──► [captcha if required by mode] ──► /login <pw> ──► [2FA code if enrolled]
      ──► authenticated (movement/chat/inventory unlocked)
```

- **Login timeout**: unauthenticated players are kicked after
  `auth.login-timeout-seconds` (0 disables).
- **Failed attempts**: after `auth.max-login-attempts` failures in one session
  the player is kicked. Captcha mode `after-failures` forces a captcha after
  `captcha.trigger-after-failures` failures.
- **IP auto-login**: a successful login records `(username, IP)` trusted for
  `ip-autologin.trust-minutes`. Reconnecting from that IP skips the password.
  With 2FA enrolled, the TOTP step is still enforced unless
  `twofa.require-with-trusted-ip: false`.

### 2FA enrollment

1. `/2fa enable` prints your base32 secret and an `otpauth://totp/...` URI.
2. Add it to Google Authenticator/Authy. **This client has no graphical UI**
   (protocol 84 predates forms entirely - only chat/tip/popup packets exist),
   so there is no scannable QR code on-screen: type the secret into the app
   via "Enter a provided key", or import the URI with an app that supports it.
3. `/2fa confirm <6-digit code>` activates 2FA and prints single-use backup
   codes **once**. Store them.
4. Backup codes work as the 2FA step (`/2fa <code>` accepts them) and are
   burned on use. Admins can regenerate with `/authadmin codes <player>`.

### Captcha modes

- `off` - never
- `always` - every join requires solving one before password entry
- `after-failures` - issued after N failed logins in the current session

Text challenges use an ambiguity-free charset; math challenges ask for a sum.
Challenges expire (`captcha.expires-seconds`) and regenerate after
`captcha.max-attempts` wrong answers.


## Architecture (DDD)

```
src/Auth/
├── Main.php                    composition root — the only place that wires concrete classes
├── config/AuthConfig.php       typed config view
├── domain/                     pure business rules, zero engine dependencies
│   ├── Account.php             aggregate root; immutable, wither-based transitions
│   ├── AccountRepository.php   persistence PORT (async-callback contract)
│   ├── AuthStage.php           auth state machine (enum)
│   ├── password/               PasswordPolicy VO + worker-side hasher statics
│   ├── twofactor/              Totp (RFC 6238), Base32, TotpSecret & BackupCodeSet VOs
│   └── captcha/                Challenge VO
├── application/                use-case orchestration
│   ├── AuthService.php         slim facade — routes to flows, no logic
│   ├── session/                AuthSession + SessionManager (O(1) hot-path maps)
│   ├── ratelimit/              escalating brute-force limiter
│   ├── captcha/                challenge generation policy
│   ├── port/                   PlayerResolver, PasswordEncoder (interfaces)
│   ├── support/Responder.php   message rendering/delivery
│   └── flow/                   one class per use case:
│       JoinFlow / RegistrationFlow / LoginFlow / CaptchaFlow /
│       TwoFactorFlow / PasswordChangeFlow / AdministrationFlow / CompletionFlow
├── infrastructure/             adapters implementing application/domain ports
│   ├── async/                  JobQueue (PasswordEncoder impl, serial DB queue),
│   │                           DbTask + HashTask (pmmpthread workers)
│   ├── storage/sqlite/         SqliteAccountRepository (port impl) + SqliteExecutor
│   │                           (worker-side PDO, dependency-free)
│   └── player/                 RestrictionListener, VisibilityFilter
└── command/                    thin CLI adapters delegating to the facade
```

Dependency rule: `command → application → domain`; `infrastructure`
implements `domain`/`application` ports; nothing in `domain` imports
`pocketmine\*`.

### Threading model (important)

### Threading model

The kernel's `ThreadingPort::submitPluginTask()` runs `PluginTask` subclasses
on real pmmpthread pool workers; results come back through `PluginFuture`
callbacks fired on the main thread next tick. The plugin uses exactly this:

- **Hashing** (`HashTask`): bcrypt cost 12 costs hundreds of ms - always run
  on workers via `JobQueue::hash()/verify()`. The main thread never hashes.
  Algorithm is auto-detected: Argon2id when the PHP build provides it
  (`PASSWORD_ARGON2ID`), otherwise bcrypt. The current build lacks Argon2,
  so bcrypt is active; rebuilding PHP upgrades transparently.
- **SQLite** (`DbTask`): the shared pool has no worker pinning (tasks land on
  arbitrary workers), so SQLite's one-reader/writer constraint is enforced at
  the queue level instead: `JobQueue` keeps **at most ONE DbTask in flight**,
  strictly FIFO, each opening its own short-lived PDO connection (WAL +
  busy_timeout). From SQLite's perspective access is perfectly sequential -
  no concurrent connections, no `SQLITE_BUSY`. Per-job connection open is
  sub-millisecond, negligible next to hash costs. If the backend is ever
  swapped for MySQL (the repository layer is interface-based), the serial
  restriction can simply be relaxed for that backend.

### Performance contract

- Auth-state checks (movement freeze, chat block, inventory gate) are a
  single `isset()` against an int-keyed in-memory map - O(1), zero I/O,
  zero allocations per event. Storage is hit once per join (async).
- Rate-limit maps are tiny flat arrays, pruned by a periodic task
  (`ratelimit.prune-interval-ticks`); they cannot grow unbounded.
- TOTP verification is pure HMAC-SHA1 (~microseconds) - main-thread, isolated
  in `Auth\domain\Totp` static functions for easy off-loading later.
- FFI/native acceleration was evaluated and deliberately skipped: after
  moving hashing off-thread, nothing hot remains on the main thread. If
  profiling ever shows otherwise (e.g. thousands of concurrent joins),
  `kh_native.so` could take over base32/TOTP glue following the
  benchmark-first pattern used elsewhere.

### Unauthenticated-player restrictions

Movement is frozen by cancelling the raw `MovePlayerPacket` in
`DataPacketReceiveEvent` (server-authoritative position stays frozen;
a MODE_RESET resync is sent on successful auth). Chat, non-auth commands,
block break/place/interact, item drops and inventory transactions are
cancelled by event. Damage to unauthenticated players can be cancelled via
config. Unauthenticated players are hidden from each other through the kernel's
per-viewer entity visibility filter (`Plugin::setEntityVisibilityFilter`):
the filter suppresses state packets for unauthenticated-viewer →
unauthenticated-target pairs, and the kernel handles the
`RemoveEntityPacket`/re-add transitions automatically when auth state flips.
The filter is O(1) per pair (two array lookups) and stable - one transition
per player lifecycle, no flicker.

## Configuration

Every subsystem is independently toggleable from `config.yml` (shipped with
inline comments). Sections: `auth`, `twofa`, `captcha`, `ratelimit`,
`ip-autologin`, `storage`, `messages`. All combinations are valid - e.g.
captcha on + 2FA off, or both off - the auth state machine treats each stage
as optional. All user-facing strings live under `messages:` with `{player}`,
`{code}`, `{seconds}`, `{min}`, `{secret}`, `{uri}` placeholders.

Keep `config.yml` present: message defaults are not duplicated in code.

## Assumptions & known limitations

- **Chat-only UI**: confirmed against the API - the 0.15.10 protocol set has
  no form/modal packets, so captcha and 2FA prompts are delivered as chat
  messages and answered via allowlisted commands.
- **Rate limits are in-memory**: intentional - they reset on restart and
  never touch storage. Escalating cooldowns still apply within uptime.
- Passwords must be at least `min-password-length`; max length is capped at
  72 bytes implicitly by bcrypt (Argon2 lifts this).

## API gaps found while building

All gaps were reported in `docs/PLUGIN_API_GAPS.md`; current status:

1. ~~`InventoryOpenEvent` not cancellable~~ — **FIXED upstream** (2026-08-23).
   Cancelling now prevents the `ContainerOpenPacket`; the plugin gates it in
   `RestrictionListener`.
2. ~~No per-viewer entity visibility filter~~ — **FIXED upstream**
   (`NetworkSessionService::setEntityVisibilityFilter`). The plugin's
   `Auth\player\VisibilityFilter` replaces the former RemoveEntity-spoofing
   workaround entirely (no sweep, no leak, no flicker).
2b. ~~`Player::isOnline()` permanently false~~ — **FIXED upstream**
   (`PlayerJoinService` sets `MetadataKeys::ONLINE=true`, leave clears it).
   Was found because the plugin's message resolution gated on it.
2c. **Futures submitted from inside a future callback are lost** — found via
   this plugin (the register flow chains hash-callback → DB write and the
   queue wedged permanently). `Kernel::drainPluginFutures()` replaces
   `pendingPluginFutures` with its `$remaining` list after iterating, which
   discards anything `trackPluginFuture()` appended during `fireCallbacks()`.
   Fix: swap-then-drain (`$draining = pending; pending = []; foreach ...`),
   so additions made during the drain survive. The plugin carries its own
   per-tick fallback drain (`JobQueue::drainOwn()`), which is redundant once
   upstream is fixed.
3. ~~Shared pool has no worker pinning~~ — **FIXED upstream**
   (`submitPluginTaskToWorker` / `Pool::submitTo`). All SQLite jobs now run
   on ONE dedicated pinned worker with a single warm PDO connection
   (per-thread connection cache in `SqliteExecutor`); a warm-up handshake
   handles pmmpthread's lazy worker spawning, with automatic round-robin
   degradation if pinning is ever unavailable.
4. **`PASSWORD_ARGON2ID` missing from the shipped PHP build** — environment,
   not API. Handled by config-driven auto-detection.


## Performance review findings (post-refactor)

Measured/inspected during the DDD refactor; nothing regressed, and these are
the remaining opportunities in priority order:

1. ~~Persistent SQLite connection~~ — **DONE**: DB tasks are pinned to
   worker 0 and `SqliteExecutor` caches one PDO connection per thread, so
   the reconnect cost (~0.1-0.5 ms/job) is paid exactly once per server
   run. Hash/verify tasks stay on the round-robin pool (parallel CPU work).
2. **`Server::getOnlinePlayers()` allocates a facade per player per call.**
   Auth only calls it once per authentication (visibility restore) and once
   per admin kick — fine. Other plugins calling it per tick should be aware.
3. **Visibility filter cost**: two array lookups per viewer→entity pair per
   tick. At 100 players × ~50 visible entities that's ~10k isset()s ≈ well
   under 0.5 ms/tick. If entity counts grow (mobs), consider short-circuiting
   by having the kernel skip the filter for non-player target types.
4. **bcrypt verify on login is the latency floor** (~300 ms at cost 12).
   That's by design (security); lower `bcrypt-cost` if login feels slow on
   weak hardware — never below 10.
5. **Rate-limiter prune** iterates all entries every `prune-interval-ticks`;
   with realistic entry counts (<100) this is microseconds. No change needed.
6. **No FFI needed**: after moving hashing off-thread, main-thread auth work
   is O(1) map lookups + tiny message formatting. kh_native.so glue would add
   complexity for unmeasurable gain (benchmark-first rule says skip).
