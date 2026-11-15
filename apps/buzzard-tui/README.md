# Buzzard TUI (React + TypeScript + Ink)

A clean, modern, and beautiful Terminal User Interface (TUI) for **Buzzard Code**, built with **React 18**, **Ink 4**, and **TypeScript 5**. Inspired by the high-craft terminal aesthetic of Claude Code and OpenCode.

## Key Features

- **⚡ Modern React + Ink Architecture:** Smooth, reactive rendering with zero Python GIL / UI blocking.
- **🎨 Sleek Styling & Layout:** Gradient badges (`gradient-string`), full-width reactive Flexbox boxes, color-coded status badges, and terminal resize responsiveness.
- **💬 Fluid Streaming Feed:** Real-time token streaming (`run/delta`), multi-line input, and markdown formatted chat.
- **🛠 Collapsible Tool Execution Cards:** Visualizes tool lifecycle with live status spinners (`ink-spinner`), command execution arguments, execution duration (ms), and output diff previews.
- **🔒 Gated Interactive Approval Modals:** Dedicated approval view with keyboard shortcuts (`[a] Allow`, `[s] Allow for Session`, `[d] Deny`), risk classification badges, and red/green diff previews.
- **✔ Authoritative Evidence Reports:** Formatted markdown presentation of the final completion gate, test execution results, exit codes, and changed-line coverage metrics.
- **🕹 Plan Mode & Slash Commands:** Instant `[Tab]` plan mode toggle, plus slash commands (`/plan`, `/tasks`, `/resume`, `/undo`, `/clear`, `/help`, `/exit`).
- **🔌 Standard Runtime Protocol:** Communicates over stdio JSON-RPC 2.0 with the headless `buzzard serve --stdio` runtime.

## Directory Structure

```
apps/buzzard-tui/
├── bin/
│   └── buzzard-tui.js         # Executable CLI launcher
├── src/
│   ├── components/
│   │   ├── ApprovalDialog.tsx # Interactive approval prompt
│   │   ├── ChatFeed.tsx       # Message list & tool stream
│   │   ├── EvidenceView.tsx   # Authoritative evidence card
│   │   ├── Header.tsx         # Gradient logo & telemetry bar
│   │   ├── StatusBar.tsx      # Shortcut legend & status
│   │   └── ToolCard.tsx       # Status spinners & execution card
│   ├── App.tsx                # Central state & input coordinator
│   ├── client.ts              # Stdio JSON-RPC runtime client
│   ├── index.tsx              # CLI entrypoint
│   └── types.ts               # Protocol and event definitions
├── package.json
└── tsconfig.json
```

## Running the React TUI

### Development mode (instant hot-execution via `tsx`)
```bash
npm run dev
```

### Build and Start
```bash
npm run build
npm start
```

### Windows Launcher
```cmd
buzzard-tui.cmd
```
