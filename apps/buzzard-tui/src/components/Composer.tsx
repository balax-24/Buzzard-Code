import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import Spinner from 'ink-spinner';
import { CommandPalette, SLASH_COMMANDS } from './CommandPalette.js';

interface ComposerProps {
  width: number;
  status: 'idle' | 'running' | 'approval_required' | 'cancelled' | 'error';
  statusText: string;
  planMode: boolean;
  onSubmit: (text: string) => void;
  onPageUp: () => void;
  onPageDown: () => void;
}

export const Composer: React.FC<ComposerProps> = ({
  width,
  status,
  statusText,
  planMode,
  onSubmit,
  onPageUp,
  onPageDown,
}) => {
  const [val, setVal] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);
  const [paletteIndex, setPaletteIndex] = useState<number>(0);

  const isCommandFilter = val.startsWith('/') && !val.includes(' ');
  const matchingCommands = isCommandFilter
    ? SLASH_COMMANDS.filter((c) => c.cmd.startsWith(val.toLowerCase())).slice(0, 5)
    : [];

  useInput((input, key) => {
    // PageUp / PageDown for transcript scrolling
    if (key.pageUp) {
      onPageUp();
      return;
    }
    if (key.pageDown) {
      onPageDown();
      return;
    }

    // Command palette selection
    if (isCommandFilter && matchingCommands.length > 0) {
      if (key.upArrow) {
        setPaletteIndex((prev) => (prev > 0 ? prev - 1 : matchingCommands.length - 1));
        return;
      }
      if (key.downArrow) {
        setPaletteIndex((prev) => (prev < matchingCommands.length - 1 ? prev + 1 : 0));
        return;
      }
      if (key.tab) {
        const chosen = matchingCommands[paletteIndex];
        if (chosen) {
          setVal(chosen.cmd + (chosen.args ? ' ' : ''));
        }
        return;
      }
    }

    // History navigation with Up/Down when input is empty
    if (key.upArrow && val === '' && history.length > 0) {
      const nextIdx = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIdx);
      setVal(history[nextIdx] || '');
      return;
    }
    if (key.downArrow && historyIndex !== -1) {
      if (historyIndex >= history.length - 1) {
        setHistoryIndex(-1);
        setVal('');
      } else {
        const nextIdx = historyIndex + 1;
        setHistoryIndex(nextIdx);
        setVal(history[nextIdx] || '');
      }
      return;
    }
  });

  const handleSubmit = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;

    // Multi-line continuation check
    if (trimmed.endsWith('\\')) {
      setVal(trimmed.slice(0, -1) + '\n');
      return;
    }

    setHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(-1);
    setVal('');
    setPaletteIndex(0);
    onSubmit(trimmed);
  };

  const isRunning = status === 'running';
  const divider = '─'.repeat(Math.max(10, width));

  return (
    <Box flexDirection="column" width={width}>
      {/* Floating command palette if typing a slash command */}
      {isCommandFilter && matchingCommands.length > 0 && (
        <CommandPalette
          width={width}
          filterText={val}
          selectedIndex={paletteIndex}
        />
      )}

      {/* Status & Activity Line */}
      <Box justifyContent="space-between" width={width}>
        <Box>
          {isRunning ? (
            <Text color="yellowBright">
              <Spinner type="dots" /> <Text dimColor>{statusText}</Text>
            </Text>
          ) : (
            <Text dimColor color="gray">{statusText}</Text>
          )}
        </Box>
        <Box gap={1}>
          <Text dimColor>Plan Mode: </Text>
          <Text color={planMode ? 'yellowBright' : 'greenBright'} bold>
            {planMode ? 'ENABLED (Read-Only)' : 'OFF (Act Mode)'}
          </Text>
        </Box>
      </Box>

      {/* Input Prompt (Claude Code Composer Style) */}
      <Box width={width} marginTop={0}>
        <Text color="greenBright" bold>❯ </Text>
        <TextInput
          value={val}
          onChange={(newVal) => {
            setVal(newVal);
            setPaletteIndex(0);
          }}
          onSubmit={handleSubmit}
          placeholder={isRunning ? 'Task in progress... (type to queue prompt)' : 'Ask Buzzard anything... (/ for commands, \\ for multi-line)'}
        />
      </Box>

      {/* Pinned Shortcut Legend */}
      <Text dimColor color="gray">{divider}</Text>
      <Box justifyContent="space-between" width={width}>
        <Box gap={1}>
          <Text color="cyanBright">[Enter]</Text>
          <Text dimColor>Send</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright">[Tab]</Text>
          <Text dimColor>Plan Mode</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright">[PgUp/Dn]</Text>
          <Text dimColor>Scroll</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright">[/diff]</Text>
          <Text dimColor>Git Changes</Text>
        </Box>
        <Box>
          <Text color="cyanBright">[Ctrl+C]</Text>
          <Text dimColor> Cancel / Quit</Text>
        </Box>
      </Box>
    </Box>
  );
};
