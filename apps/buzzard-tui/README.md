# Buzzard TUI & Buzzard Go CLI (React 18 + TypeScript + Ink 4)

A clean, modern, and beautiful Terminal User Interface (TUI) for **Buzzard Code** and **Buzzard Go**, built with **React 18**, **Ink 4**, and **TypeScript 5**. Engineered to match and exceed the terminal UX, aesthetic, and responsiveness of Anthropic's **Claude Code** and Google's **Gemini CLI**.

## Architecture & Claude Code Parity

1. **Animated Buzzard Falcon Brand Identity (`<BuzzardLogo />` & `<BuzzardSpinner />`):**
   - Replaces generic spinners with an animated cyber-falcon raptor morphing across 8 fluid frames (`⟨⠋ 🦅 ⠙⟩` → `⟨⠙ ⚡ ⠚⟩` → `⟨⠹ ◈ ⠒⟩` → `⟨⠼ ⚡ ⠄⟩` → `⟨⠴ ◈ ⠤⟩`) with electric gradient styling (`#00F2FE` → `#4FACFE` → `#7B2CBF` → `#0072FF`).
   - Morphing wing beats and lightning surges during active tool execution and thinking phases.
   - Claude Code-style ASCII Hero Welcome display with quick commands, keyboard shortcuts, active model badges, and project starters.

2. **Alternate Screen Buffer (`\x1b[?1049h` / `\x1b[?1049l`):**
   - Renders on a dedicated full-screen canvas.
   - Completely eliminates screen jumping, text tearing, and the multi-header re-render bug on Windows `cmd.exe` and Windows Terminal.
   - Restores the original terminal scrollback cleanly on exit.

3. **Responsive Dual-Pane Docked Layout (Claude Code standard):**
   - **Wide Screens (`columns >= 110`):** Automatically docks a 36-column **Session Inspector** sidebar to the right of the main chat transcript, displaying real-time git branch, uncommitted files, `+insertions/-deletions` diff statistics, durable tasks, and safety state.
   - **Narrow Screens (`columns < 110`):** Gracefully falls back to a single full-width transcript layout.

4. **Live `/diff` Inspector (`<DiffModal />`):**
   - Interactive full-screen colored unified diff viewer (`+` green, `-` red, `@@` cyan, `diff` yellow) with `PageUp`/`PageDown` keyboard scrolling, toggled via `/diff` or closed via `Esc`/`q`.

5. **Claude Code Composer Aesthetic (`<Composer />`):**
   - Pinned bottom bar with status activity spinner, input prompt (`❯`), prompt history (Up/Down arrows), and multi-line continuation (`\`).
   - Autocomplete popover for slash commands with `Tab` completion and arrow key navigation.

6. **Full Slash Command Ecosystem:**
   - `/diff`: Interactive live unified git diff inspector
   - `/plan [on|off]`: Toggle safe read-only plan mode (blocks edits & commands)
   - `/tasks`: List unfinished durable tasks across sessions
   - `/resume <id>`: Resume an interrupted durable task from disk
   - `/undo`: Instant rollback of the last applied file edit
   - `/cost`: Display session token accounting and cost estimate
   - `/model [name]`: Display active model info or switch model routing
   - `/doctor`: Run complete environment, security, and tool diagnostics
   - `/init`: Analyze workspace architecture and generate context summary
   - `/clear`: Clear conversation transcript
   - `/help`: Show command and keyboard shortcut reference
   - `/exit`: Clean shutdown

7. **Gated Interactive Approval Dialogs (`<ApprovalDialog />`):**
   - Dedicated modal with risk level classification badges (`HIGH RISK`, `MEDIUM`), command/diff previews, and single-keypress decisions (`[a] Allow Once`, `[s] Allow for Session`, `[d] Deny`).

## Directory Structure

```
apps/buzzard-tui/
├── bin/
│   └── buzzard-tui.js         # Executable CLI launcher
├── src/
│   ├── components/
│   │   ├── ApprovalDialog.tsx # Interactive gated approval modal
│   │   ├── BuzzardLogo.tsx    # Animated Falcon brand logo, spinner & welcome hero
│   │   ├── CommandPalette.tsx # Floating slash command popover
│   │   ├── Composer.tsx       # Pinned bottom input & status bar
│   │   ├── DiffModal.tsx      # Unified git diff viewer
│   │   ├── Header.tsx         # Pinned top header & telemetry
│   │   ├── Sidebar.tsx        # Docked inspector sidebar (when wide >= 110)
│   │   ├── ToolCard.tsx       # Compact tool execution status
│   │   └── Transcript.tsx     # Bounded scrollable message transcript
│   ├── hooks/
│   │   └── useTerminalSize.ts # Responsive resize hook
│   ├── terminal/
│   │   └── screen.ts          # Alternate screen buffer manager
│   ├── workspace/
│   │   └── gitStatus.ts       # Live porcelain git status & diff parser
│   ├── App.tsx                # Central layout coordinator
│   ├── client.ts              # Stdio JSON-RPC runtime client
│   ├── index.tsx              # CLI entrypoint
│   └── types.ts               # Protocol and event definitions
├── buzzard-tui.cmd            # Windows batch launcher (buzzard-tui)
├── buzzard-go.cmd             # Windows batch launcher (buzzard-go)
├── package.json
└── tsconfig.json
```

## Running Buzzard TUI & Buzzard Go

From Windows command line or terminal:

```cmd
cd apps/buzzard-tui

:: Build TypeScript
npm run build

:: Run with node
npm start

:: Or launch directly with either Windows launcher
buzzard-tui.cmd
:: or
buzzard-go.cmd
```
