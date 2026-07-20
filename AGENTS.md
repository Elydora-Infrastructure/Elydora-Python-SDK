# Elydora Python SDK Engineering Contract

## Scope

This repository owns the published `elydora` package, its CLI, synchronous and asynchronous API clients, local signing behavior, generated hook runtimes, and Python-specific agent adapters.

## Integration Sources

- Verify every agent hook contract against current official provider documentation before changing an adapter.
- Treat `../Elydora-Open-Source/integrations/catalog.json` as the cross-product provider inventory.
- Keep the exported `INTEGRATION_TYPES` tuple aligned with that inventory, and require `integration_type` in every agent registration request.
- Keep adapter delivery claims aligned with executable tests in this repository.
- Synchronize completed provider behavior into the Node SDK, Go SDK, Open Source distribution, Console, Docs, and landing page through separate reviewed commits.

## Hook Adapter Invariants

- Preserve unrelated user configuration and remove only Elydora-owned entries.
- Parse every affected user configuration before the first write.
- Surface malformed or unreadable configuration with contextual errors and leave the original file intact.
- Write configuration through a same-directory temporary file followed by an atomic replace.
- Quote the current Python executable and generated script paths for the host shell.
- Forward official hook JSON from STDIN without reshaping provider fields.
- Use the provider's documented blocking mechanism. Command-hook providers that define exit code `2` must receive exit code `2` from the freeze guard.
- Report installation as healthy only when a complete hook contract references both generated runtime scripts and both scripts exist.
- Write Cursor hooks only to `~/.cursor/hooks.json`; keep project and enterprise sources read-only. Preserve user hooks, migrate the prior versionless Elydora contract, and own exact native `preToolUse`, `postToolUse`, and `postToolUseFailure` commands. Forward native success and failure payloads, retain PowerShell exit code `2`, set every handler to `failClosed` with a bounded timeout, and commit the guard, audit script, runtime identity, private key, and hook configuration as one rollback-capable transaction.
- Model stable, legacy, and early-access hook generations as explicit contracts. Keep their activation requirements visible in CLI output and README guidance.
- Resolve stable Kimi hooks through `$KIMI_CODE_HOME/config.toml` with `~/.kimi-code/config.toml` as the default, and treat an empty override as the default. Activate `~/.kimi/config.toml` only when the legacy home exists. Register exact `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` rules with ten-second commands; stable Kimi supports its current sixteen-event schema and legacy kimi-cli supports its thirteen-event schema. Preserve TOML comments and array style, then parse the complete rendered document before staging it. Preserve the native snake_case payload, propagate exit code `2`, and keep audit delivery fail-open with owner-only error logs. Use encoded PowerShell commands on Windows and exact two-argument shell commands on Unix. Commit every detected config, generated runtime, runtime config, and private key through one rollback-capable transaction.
- Resolve Grok Build user hooks through `$GROK_HOME/hooks/*.json` with `~/.grok/hooks/*.json` as the default, and treat an empty override as the default. Keep Claude Code, Cursor, project `.grok/hooks`, plugin, and `hooks-paths` sources read-only. Register exact `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` groups with ten-second command handlers, preserve the complete native camelCase payload, and emit Grok's documented deny JSON plus exit code `2` for frozen or revoked agents. Use encoded PowerShell commands on Windows and exact two-argument shell commands on Unix. Commit Grok's hook file, generated runtimes, runtime config, and private key through one rollback-capable transaction.
- Resolve Claude Code user hooks through `$CLAUDE_CONFIG_DIR/settings.json` with `~/.claude/settings.json` when the variable is absent. Match Claude Code's path resolution exactly: relative and empty values resolve from the current working directory, and literal tildes remain path segments. Keep project, local, managed, plugin, skill, and agent hook sources read-only. Validate the complete shipped handler schema, including command exec form, async rewake metadata, HTTP, MCP tool, prompt, and agent handlers. Register exact matchless `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` groups with ten-second exec-form command handlers. Preserve the complete native snake_case payload and propagate freeze and revocation through exit code `2`. Commit Claude Code's user settings, generated runtimes, runtime config, and private key through one rollback-capable transaction. Reject installation while the user source sets `disableAllHooks`, then require `/hooks` and `claude doctor` verification for higher-scope policy effects.
- Resolve Gemini CLI user hooks through `$GEMINI_CLI_HOME/.gemini/settings.json` with `~/.gemini/settings.json` when the variable is absent or empty. Preserve relative and literal-tilde home values as Gemini CLI does. Keep workspace, system defaults, system overrides, and extension hooks read-only. Preserve JSON comments while rejecting trailing commas and duplicate keys. Register exact matchless `BeforeTool` and `AfterTool` groups named `elydora-guard` and `elydora-audit` with ten-second command handlers. Preserve the complete native snake_case payload, emit valid JSON on exit code `0`, and propagate freeze and revocation through exit code `2`. Use encoded PowerShell commands on Windows. Commit Gemini CLI user settings, generated runtimes, runtime config, and private key through one rollback-capable transaction. Respect `hooksConfig.enabled` and `hooksConfig.disabled`, then require `/hooks list` verification for higher-scope policy effects.
- Resolve Auggie user hooks through `~/.augment/settings.json`; keep system, workspace, local workspace, and alternate `--augment-cache-dir` settings read-only. Validate the shipped Auggie 0.33 hook schema: `PreToolUse`, `PostToolUse`, `Stop`, `SessionStart`, `SessionEnd`, `Notification`, and `PromptSubmit`; regex matchers belong to tool events, command handlers use string-array arguments and positive millisecond timeouts, and metadata flags are booleans. Generate `.cmd` wrappers on Windows and `.sh` wrappers on Unix, preserve the complete native snake_case payload, and propagate freeze and revocation through exit code `2`.
- Validate Auggie matcher syntax during installation with Node.js `new RegExp`; keep status and uninstall independent from the JavaScript validator so recovery remains available offline. Commit Auggie settings, both wrappers, generated runtimes, runtime config, and private key through one rollback-capable transaction. Require exact runtime identity, canonical private keys, physical files, and exact wrapper sources during status checks, then verify the effective configuration with `auggie tools list`.
- Treat Cline 3 CLI file hooks as the adapter contract. Resolve hooks additively from `~/Documents/Cline/Hooks`, `$CLINE_DIR/hooks` with `~/.cline/hooks` as the default, `.clinerules/hooks`, and `.cline/hooks`; write only the `$CLINE_DIR` source. Preserve the complete hybrid CLI payload, resolve generated Python runtimes from absolute shebangs, and emit one-line JSON stdout with `cancel: true` for guard exit code `2`. Commit both wrappers, generated runtimes, runtime config, and private key through one rollback-capable transaction. Status requires physical files, canonical private keys, exact runtime identity, exact generated sources, and exact wrapper sources. Hook errors, timeouts, and invalid controls fail open in Cline while remaining observable.
- Resolve Codex user hooks through `$CODEX_HOME/hooks.json` with `~/.codex/hooks.json` as the default, matching Codex's existing-directory canonicalization rule. Preserve additive user TOML, project, plugin, and managed sources. Register exact `PreToolUse` and `PostToolUse` match-all command groups with ten-second handlers, preserve the complete native payload, propagate freeze and revocation through exit code `2`, keep guard lookup and audit delivery fail-open with observable errors, and commit user hooks plus all four runtime artifacts through one rollback-capable transaction. Require `/hooks` approval for both definition hashes.
- Write Factory Droid hooks only to user-level `~/.factory/hooks.json`, its active legacy fallback, or the `hooks` object in `~/.factory/settings.json`; keep project and organization sources read-only. Preserve JSONC syntax, select sources per event, store direct event maps in hook files, keep settings hooks nested, validate JavaScript matchers before installation, use exact command ownership, and instruct users to review changes through `/hooks`.
- Resolve Qwen Code user settings through explicit `QWEN_HOME`, `~/.qwen/.env`, then `~/.env`; keep workspace settings read-only. Preserve comments while rejecting trailing commas and duplicate keys, store hooks under the nested `hooks` object, treat `disableAllHooks` as unhealthy, validate JavaScript matchers before installation, use millisecond timeouts and explicit host shells, preserve PowerShell native exit codes, and instruct users to review changes through `/hooks`.

## Code Quality

- Keep the package, distribution, and CLI version in `elydora/_version.py`; build metadata must read that literal through Setuptools dynamic metadata.
- Ship `elydora/py.typed` in every wheel and verify public annotations from an installed-wheel consumer.
- Support every Python version declared in `pyproject.toml`.
- Keep production source files at or below 500 lines.
- Keep functions focused on one ownership boundary.
- Propagate unexpected errors to the CLI boundary.
- Use documented defaults only for genuinely optional configuration.
- Avoid compatibility shims without a named public or user configuration contract.
- Resolve every agent runtime directory as one physical child of `~/.elydora`; reject separators, traversal segments, cross-platform reserved names, symbolic-link directories, and linked identity configs before writes or recursive removal. Validate stored directory identity before changing host CLI configuration, and require an explicit agent ID when discovery is ambiguous.
- Accept CLI install credentials through hidden terminal input or physical owner-only credential files. Keep credentials out of process arguments, reject legacy secret options with redacted errors, and require one UTF-8 line of at most 64 KiB.
- Persist the signing key once at `~/.elydora/<agent-id>/private.key` with mode `0600`. Generated audit runtimes read and validate that physical file at execution time.
- Read runtime config, private keys, status cache, chain state, and error logs through physical-file descriptors with identity checks. Write cache and chain state atomically, and append error logs through no-follow owner-only descriptors.
- Write runtime secrets, generated scripts, and provider configuration through same-directory temporary files followed by atomic replacement. Surface permission and replacement failures.
- Interpret `max_retries` as retries after the initial attempt and reject negative or non-integer values.
- Automatically retry RFC-idempotent methods; retry non-idempotent methods only when the transport proves the request was never sent.
- Honor valid `Retry-After` delay-seconds and HTTP-date values, and release retryable responses before sleeping.

## Verification

Run the focused adapter test during development, then execute all release gates before commit:

```powershell
py -3 -m pytest tests/test_<provider>_plugin.py -q
py -3 -m pytest -q
py -3 -m mypy elydora
py -3 -m pip check
py -3 -m pip wheel . --no-deps --wheel-dir <temporary-directory>
git diff --check
```

Provider adapter tests must cover installation, idempotency, official event forwarding, blocking behavior, status, missing runtime files, uninstall ownership, and malformed configuration preservation.

Commit and push one root issue before starting the next one.
