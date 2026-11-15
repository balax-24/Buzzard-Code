import { render, Instance } from 'ink';
import React from 'react';

/**
 * Runs a React Ink application cleanly in standard terminal interactive mode,
 * matching the architecture of Claude Code and Gemini CLI.
 * 
 * - Preserves standard terminal scrollback
 * - Zero alternate buffer scrolling glitches on Windows cmd.exe / PowerShell
 * - Restores cursor cleanly on exit
 */
export function runCliApp(element: React.ReactElement): Instance {
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    try {
      if (process.stdout.isTTY) {
        process.stdout.write('\x1b[?25h'); // Ensure cursor is visible
      }
    } catch {
      // Ignore errors on process shutdown
    }
  };

  process.on('exit', cleanup);
  process.on('SIGINT', () => {
    cleanup();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(0);
  });
  process.on('uncaughtException', (err) => {
    cleanup();
    console.error('Fatal TUI Exception:', err);
    process.exit(1);
  });

  const instance = render(element, {
    exitOnCtrlC: false, // The App component handles Ctrl+C gracefully
  });

  instance.waitUntilExit().finally(() => {
    cleanup();
  });

  return instance;
}

export const runFullScreenApp = runCliApp;
