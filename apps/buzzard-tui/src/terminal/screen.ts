import { render, Instance } from 'ink';
import React from 'react';

/**
 * Runs a React Ink application inside the terminal's Alternate Screen Buffer.
 * 
 * This completely eliminates:
 * 1. Screen flickering & jumping
 * 2. Duplicate header / box re-rendering on Windows cmd / PowerShell / Terminal
 * 3. Terminal scrollback pollution
 * 
 * On exit, it cleanly restores the user's original terminal screen and cursor.
 */
export function runFullScreenApp(element: React.ReactElement): Instance {
  // Enter alternate screen buffer & clear display
  process.stdout.write('\x1b[?1049h\x1b[H\x1b[2J');

  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    try {
      // Show cursor & restore main screen buffer
      process.stdout.write('\x1b[?25h\x1b[?1049l');
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
