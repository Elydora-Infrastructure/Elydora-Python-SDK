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
- Write Cursor hooks only to `~/.cursor/hooks.json`; keep project and enterprise sources read-only. Preserve user hooks, migrate the prior versionless Elydora contract, use exact native command ownership, retain PowerShell exit code `2`, and set security-critical handlers to `failClosed` with a bounded timeout.
- Model stable, legacy, and early-access hook generations as explicit contracts. Keep their activation requirements visible in CLI output and README guidance.
- Select Kimi Code and legacy kimi-cli config targets from existing runtime evidence; a fresh installation targets current Kimi Code and keeps migration markers isolated to active runtimes.
- Keep Grok Build writes inside its native global `$GROK_HOME/hooks/*.json` contract. Treat Claude Code and Cursor compatibility files plus project `.grok/hooks` as read-only integration sources.
- Write Auggie hooks only to `~/.augment/settings.json`; keep system and workspace settings read-only. Generate `.cmd` wrappers on Windows and `.sh` wrappers on Unix because Auggie dispatches supported script paths, and express hook timeouts in milliseconds.
- Validate Auggie matcher syntax during installation with Node.js `new RegExp`; keep status and uninstall independent from the JavaScript validator so recovery remains available offline.
- Write Cline hooks only to `$CLINE_DIR/hooks` with `~/.cline/hooks` as the default; keep Documents and workspace hook roots read-only. Preserve official input byte-for-byte, resolve Python runtimes from their absolute shebangs, and translate guard exit code `2` into Cline's JSON stdout cancellation control.
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
