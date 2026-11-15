# Buzzard TUI (React + TypeScript + Ink)

A clean, modern, and beautiful Terminal User Interface (TUI) for **Buzzard Code**, built with **React 18**, **Ink 4**, and **TypeScript 5**. Engineered with the production-grade terminal patterns of Anthropic's **Claude Code** and Google's **Gemini CLI**.

## Architecture & Design (Parity with Claude Code & Gemini CLI)

1. **Alternate Screen Buffer (`\x1b[?1049h` / `\x1b[?1049l`):**
   - Renders on a dedicated full-screen canvas.
   - Completely eliminates screen jumping, text tearing, and the multi-header re-render bug on Windows `cmd.exe` and Windows Terminal.
   - Restores the original terminal scrollback cleanly on exit.

2. **Responsive Dual-Pane Docked Layout (Claude Code standard):**
   - **Wide Screens (`columns >= 110`):** Automatically docks a 34-column **Session Inspector** sidebar to the right of the main chat transcript, displaying files touched, durable tasks, plan mode safety, and telemetry.
   - **Narrow Screens (`columns < 110`):** Gracefully falls back to a single full-width transcript layout.

3. **Fixed Bounded Viewport & Transcript Slicing:**
   - The total layout height strictly respects `process.stdout.rows`.
   - The middle transcript slices content dynamically so vertical overflow never causes the terminal to scroll or lose cursor tracking.
   - Seamless tail auto-scrolling with `PageUp` and `PageDown` history navigation.

4. **Claude Code Composer Aesthetic:**
   - Pinned bottom bar with status activity spinner (`ink-spinner`), input line (`❯`), prompt history (Up/Down arrows), and multi-line continuation (`\`).
   - Autocomplete popover for slash commands (`/plan`, `/tasks`, `/resume`, `/undo`, `/clear`, `/help`, `/exit`).

5. **Gated Interactive Approval Dialogs:**
   - Dedicated modal with risk level classification badges (`HIGH RISK`, `MEDIUM`), command/diff previews, and single-keypress decisions (`[a] Allow Once`, `[s] Allow for Session`, `[d] Deny`).

6. **Authoritative Evidence Reports:**
   - Directly renders the completion gate results, test counts, exit codes, and changed-line coverage metrics inside the transcript.

## Directory Structure

```
apps/buzzard-tui/
├── bin/
│   └── buzzard-tui.js         # Executable CLI launcher
├── src/
│   ├── components/
│   │   ├── ApprovalDialog.tsx # Interactive approval modal
│   │   ├── Composer.tsx       # Pinned bottom input & status bar
│   │   ├── Header.tsx         # Pinned top header & telemetry
│   │   ├── Sidebar.tsx        # Docked inspector sidebar (when wide)
│   │   ├── ToolCard.tsx       # Compact tool execution status
│   │   └── Transcript.tsx     # Bounded scrollable message transcript
│   ├── hooks/
│   │   └── useTerminalSize.ts # Responsive resize hook
│   ├── terminal/
│   │   └── screen.ts          # Alternate screen buffer manager
│   ├── App.tsx                # Central layout coordinator
│   ├── client.ts              # Stdio JSON-RPC runtime client
│   ├── index.tsx              # CLI entrypoint
│   └── types.ts               # Protocol and event definitions
├── package.json
└── tsconfig.json
```

## Running the React TUI

From Windows command line or terminal:

```cmd
cd apps/buzzard-tui

:: Development mode (instant hot-execution via tsx)
npm run dev

:: Build and run
npm run build
npm start

:: Or launch directly with the Windows launcher
buzzard-tui.cmd
```
