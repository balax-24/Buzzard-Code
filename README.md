# Buzzard Code

**Understand. Plan. Build. Verify. Secure.**

A terminal coding agent built around one rule: it cannot call a task done until the code proves it.

> The model proposes. Code decides.

Coding agents can report success while tests are failing. In Buzzard, a deterministic completion gate checks the real git state and runs the project's real test suite. If the tests fail, the task cannot finish, whatever the model says.

## Results on Meta models

Tested with Muse Glimmer (`meta/muse-glimmer-30b`) through OpenRouter on a disposable repository. The scenario explains the code, finds a deliberate bug, fixes it, recovers from a test failure introduced mid-run, and checks the audit records. Outcomes are verified independently with git and pytest, not taken from the agent.

| Run | Result |
|---|---|
| Before fix | 13/17: found a real defect where the agent reported `completed` while tests failed |
| After fix | **17/17** |

That is one passing run on one small scenario, not a benchmark or a reliability figure. Reproduce it with the command under [Acceptance test](#acceptance-test).

## Features

**Verification and control**
- Completion gate that runs real tests and cannot be bypassed by the model
- Approval for every edit and command, showing the exact change; only `y` approves
- `/plan` mode: edits and commands are refused in code, not by asking the model
- `/undo` for the agent's file edits, with conflict detection
- Secret-named environment variables removed from agent-run commands
- Stops a model that keeps repeating the same action

**Working in your terminal**
- `@file` mentions with autocomplete
- Project instructions from `BUZZARD.md`, `AGENTS.md` or `CLAUDE.md`
- Token and context meter, plus transcript with coloured diffs
- Follow-up context, `/continue`, `/compact`, `/export`
- `/git`, `/log`, `/diff`, `/files`, `/review`, `/test`, `/usage`; Esc to interrupt

**Models and tools**
- Meta models through the Meta Model API or any OpenAI-compatible host
- Also OpenAI, Anthropic, Gemini and local Ollama, with native tool calling
- MCP client for stdio servers, with approval on every call

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/balax-24/Buzzard-Code.git
cd Buzzard-Code
uv sync
```

Run on Muse Glimmer through OpenRouter (macOS/Linux shown):

```bash
export OPENAI_COMPATIBLE_API_KEY="your-openrouter-key"
export OPENAI_COMPATIBLE_BASE_URL="https://openrouter.ai/api/v1"
uv run buzzard tui --model openai-compatible/meta/muse-glimmer-30b
```

For the Meta Model API, set `META_API_KEY` and use `--model meta/muse-spark-1.1`. The Meta Model API provider has been tested against mocked responses only.

Set `BUZZARD_MAX_OUTPUT_TOKENS` to cap output per request when your credit balance is small.

## Acceptance test

```bash
uv run python experiments/acceptance/run_ollama_acceptance.py --provider openai-compatible --model meta/muse-glimmer-30b
```

Results are written to `artifacts/acceptance/`.

## MCP servers

Servers load only from `~/.buzzard/mcp.json`, never from a repository, because starting a server runs its command on your machine.

```json
{"mcpServers": {"docs": {"command": "npx", "args": ["my-server"]}}}
```

## Security notes

Without Docker, approved commands run on your machine as your user with **no isolation**, so your approval is the safeguard. Read each command, and use Docker for untrusted code.

This project began as a security assessment agent, and that tooling remains in `security_agent/tools`. Only use it on systems you are authorized to test.

## Limitations

No subagents, repository indexing or multi-line input yet. MCP supports stdio tools only. A passing gate proves only what the project's tests check.

## Tests

```bash
uv run --group dev pytest
```
