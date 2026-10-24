# pi-auto-review

**English** | [简体中文](README.zh-CN.md)

Regex + optional LLM review for [Pi](https://pi.dev)'s `bash` tool calls.

Review shell commands before the Agent executes them: allowlisted commands run directly, commands matching risk patterns require confirmation, and other commands are evaluated by a review model.

> **This is a heuristic review tool, not a sandbox or a complete security boundary.** Both regex rules and LLMs can miss risks. Use isolation and least privilege for untrusted code, sensitive data, or unattended tasks.

## Installation

Requires Pi. This extension uses the `@earendil-works/pi-coding-agent` extension API and has been used with Pi **1.4.0**. Current Pi requires Node.js **22.19+**.

Install directly from GitHub; npm publication is not required:

```bash
pi install git:github.com/Benature/pi-auto-review
```

Run `/reload` in Pi after installation, or restart Pi. When enabled, the extension displays this startup notification (currently in Chinese):

```text
pi-auto-review 已加载 (mode=llm, strict=false)
```

Update or uninstall:

```bash
pi update git:github.com/Benature/pi-auto-review
pi remove git:github.com/Benature/pi-auto-review
```

For local development or a one-off trial:

```bash
git clone https://github.com/Benature/pi-auto-review.git
cd pi-auto-review
pi --extension ./src/pi-auto-review.ts
```

Pi loads TypeScript directly; no build step is needed. **Use only one loading method.** Do not load the same extension through both a package installation and a copied file or symlink, as this can cause duplicate reviews and prompts.

## Default behavior

`PI_AUTO_REVIEW_MODE` defaults to `llm`. Commands pass through these stages in order:

| Stage | Condition | Behavior |
| --- | --- | --- |
| Risk regex | Matches a built-in risk pattern | Ask for confirmation; block without a UI |
| Allowlist | Matches a command prefix and basic composition checks | Execute directly without calling the review LLM |
| LLM review | Matches neither of the previous stages | Allow if `safe: true`; otherwise ask for confirmation |
| Review unavailable | No model or credentials, failed request, or unparseable result | Ask for confirmation; block without a UI |

- Risk patterns cover some recursive deletions, `sudo`, permissive permissions, disk overwrites, destructive Git operations, and remote scripts piped into a shell. **Coverage is not exhaustive.**
- The allowlist includes `ls`, `pwd`, `grep`, and `git status`, but also commands whose arguments can have side effects. An allowlist match **does not prove that a command is read-only**.
- In `regex` mode, no review LLM is called. Commands matching neither risk patterns nor the allowlist also require confirmation.
- In `off` mode, no review handler is registered; all checks and notifications above are disabled.
- LLM verdicts are cached in extension memory by the complete command string. Repeated commands reuse the verdict, but unsafe results still follow the confirmation or blocking policy. The cache is not persisted and is cleared on reload.

## Configuration

All extension settings come from the Pi **process environment**. Personal endpoints and credentials are not stored in this repository.

| Environment variable | Default | Description |
| --- | --- | --- |
| `PI_AUTO_REVIEW_MODE` | `llm` | `llm`: regex + LLM; `regex`: regex and manual confirmation only; `off`: disabled |
| `PI_AUTO_REVIEW_MODEL` | Unset | A registered Pi `provider/model-id`; selected automatically when unset |
| `PI_AUTO_REVIEW_STRICT` | `0` | Set to `1` to block an unsafe LLM verdict without allowing a manual override |

**`STRICT` only affects unsafe LLM verdicts.** It does not prevent manual approval of commands matching risk patterns or manual confirmation when review is unavailable. It is not a global “block all risks” switch.

Choose a review model for one invocation:

```bash
PI_AUTO_REVIEW_MODEL='your-provider/your-model-id' pi
```

Use regex only:

```bash
PI_AUTO_REVIEW_MODE=regex pi
```

Fix the review model and disallow overrides of unsafe LLM verdicts:

```bash
PI_AUTO_REVIEW_MODEL='your-provider/your-model-id' PI_AUTO_REVIEW_STRICT=1 pi
```

For persistent configuration, add `export PI_AUTO_REVIEW_MODEL='your-provider/your-model-id'` to the shell configuration or script used to launch Pi, then launch Pi from a shell that has loaded the updated environment.

### Automatic model selection

No provider or model names are hardcoded:

1. Use the model specified by `PI_AUTO_REVIEW_MODEL` if it can be found in the registry.
2. If unset or not found, select the model with the lowest `cost.input + cost.output` from `ctx.modelRegistry.getAvailable()`.
3. For equal prices, keep the **first model in registry order**; names are not sorted separately.
4. If the available list is empty, try the current session model. If no model or configured authentication is available, fall back to manual confirmation.

This is a rough comparison based on Pi's pricing metadata, **not a guarantee of the lowest actual bill**. Pi may assign a price of `0` to custom models without pricing, making them preferred; that does not mean they are free. Supply accurate pricing or explicitly choose a review model.

The first selected model is reused for the current extension runtime. Switching the session model does not automatically reselect it. If an explicitly selected model exists but authentication or requests fail, the extension does not cycle through other models.

### Base URL, API token, and model ID

The extension reuses Pi's provider configuration; it has no separate Base URL or token settings. Configure a custom compatible endpoint in **`~/.pi/agent/models.json`**. If `PI_CODING_AGENT_DIR` is set, use `models.json` in that directory.

This example contains placeholders only. Merge it into your existing `providers` rather than replacing other configuration:

```json
{
  "providers": {
    "your-provider": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$REVIEW_API_TOKEN",
      "models": [
        { "id": "your-model-id" }
      ]
    }
  }
}
```

- `baseUrl`: the service's API endpoint.
- `apiKey`: preferably a reference to a local environment variable or another secure credential source. Never commit real tokens.
- `models[].id`: the model ID accepted by the service.
- `api`: the protocol the endpoint actually supports; do not assume every endpoint is OpenAI-compatible.

For built-in providers, Pi's `/login` can also configure authentication. See the [Pi model configuration documentation](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md) for more fields.

### Review requests and thinking

Requests currently use `maxTokens: 4096` and send `reasoning_effort: "low"` to applicable OpenAI-compatible APIs. **This does not disable thinking**, and provider support varies.

The extension first tries to parse a complete `{ "safe": ..., "risk": ..., "reason": ... }` from the text response, then tries JSON in the thinking blocks. The parser accepts a complete JSON code fence and correctly handles braces, quotes, and escapes in the reason. It requires a boolean `safe`, a `risk` of `none`, `low`, `medium`, or `high`, and a nonempty string `reason`.

Only responses with `stopReason: "stop"` are parsed as verdicts. Returned provider errors (`stopReason: "error"`) show the model and the provider's `errorMessage`, rather than being mislabeled as invalid JSON. Failed or unfinished responses are never cached or automatically approved; they require manual confirmation, or are blocked without a UI. Cancelled reviews are blocked without opening a confirmation prompt.

It does not extract partial JSON from explanatory prose or accept multiple verdict objects or truncated JSON. Parse failures require manual confirmation. The thinking fallback still cannot be treated as reliable verification of a final verdict.

## Verification

**Ask the Agent in natural language to execute commands using its `bash` tool.** Do not use direct `!` or `!!` commands to test review:

| Example command | Expected path |
| --- | --- |
| `ls -la` | The original command matches the allowlist and runs silently |
| `sudo --version` | Matches a risk pattern and asks for confirmation; choose rejection to avoid executing it |
| `curl -s https://example.com -o /tmp/pi-auto-review-example.html` | Goes through LLM review by default; the verdict depends on the model |

An approved LLM verdict produces a notification such as `shell-review ✓ low — ...`. A command producing no stdout **does not mean it was not reviewed**.

Other extensions, such as command wrappers, may rewrite commands first and cause an otherwise allowlisted command to go through LLM review. Processing order depends on Pi's extension registration order.

## herdr integration

With a compatible herdr Agent-state integration installed, every confirmation prompt reports its waiting-for-answer state through Pi's event bus:

```ts
// Before the prompt
pi.events.emit("herdr:blocked", {
  active: true,
  label: "pi-auto-review: 等待确认 shell 命令"
});

// After an answer, cancellation, or dialog exception (finally)
pi.events.emit("herdr:blocked", { active: false });
```

herdr displays the blocked state and restores the working state. Without an integration listening for this event, the events have no UI effect and require no additional dependency. The event label above reflects the current Chinese UI text.

## Logs and privacy

When review is enabled, the extension attempts to append diagnostic logs to:

```text
~/.pi/agent/extensions/pi-auto-review.log
```

Logs include **complete command strings**, LLM approval reasons, errors, and excerpts of unparseable model output. They are **not redacted or automatically rotated**. Tokens, paths, or personal information appearing in commands will also appear in logs. Inspect logs before sharing them, and do not commit local logs to the repository.

- The log path is currently fixed and does not follow `PI_CODING_AGENT_DIR`.
- Writes are silently skipped if the directory does not exist or is not writable.
- There is no independent logging switch; `MODE=off` disables the entire review extension.
- LLM review sends the command to the selected provider. `regex` mode avoids this additional review request but does not change how Pi's main conversation model processes data.

## Troubleshooting and safety boundaries

- **Source changes:** `/reload` reloads extensions. **Shell environment changes:** restart Pi from a shell that has loaded the new environment. `/reload` does not reread `.zshrc`, and `export` in a child process does not change the parent Pi process's environment.
- **Review unavailable:** distinguish a provider request failure from a JSON parse failure. For `stopReason=error`, check the displayed `errorMessage` for authentication, quota/rate-limit, connectivity, or upstream failures. For `stopReason=length`, the token budget was exhausted before review completed. Only normally finished responses with malformed JSON are reported as unparseable output.
- **Only `tool_call` events named `bash` are intercepted.** This does not cover direct user `!` or `!!` commands, `powershell`, `edit` or `write`, processes launched directly by extensions, or all MCP tools.
- **Not a complete shell parser:** prefixes, pipelines, substitutions, arguments, scripts, and indirect invocations can cause false positives or missed risks.
- **Not an operating-system permission boundary:** LLMs can misjudge commands or be influenced by prompt injection. The cache does not track file or environment changes. Use containers, VMs, OS sandboxes, and least privilege when strong protection is required.

## Local tests

Run `npm test` from the repository (Node.js 22.19+, no additional dependencies required). Tests cover braces and escapes in JSON reasons, code fences, invalid fields, truncated output, and review hooks with mocked LLM responses. They do not call real models or execute reviewed shell commands.

## npm publication

**Publishing to npm is not required to install this extension.** Use the GitHub installation method above. This project has not been published to npm.

`package.json` declares `pi.extensions` so Pi can discover `src/pi-auto-review.ts` and includes the `pi-package` keyword. To prevent accidental publication, it currently sets `private: true`. An open-source license has not yet been selected (`UNLICENSED`).

Before publishing to npm, choose an available package name or scope, a license, a versioning policy, and release checks, then remove `private`. Users could then install with `pi install npm:<actual-package-name>`; this is not a working installation method until a package is actually published.
