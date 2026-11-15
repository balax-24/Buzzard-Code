import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import Spinner from 'ink-spinner';

interface ComposerProps {
  width: number;
  status: 'idle' | 'running' | 'approval_required' | 'cancelled' | 'error';
  statusText: string;
  planMode: boolean;
  onSubmit: (text: string) => void;
  onPageUp: () => void;
  onPageDown: () => void;
}

const COMMAND_HINTS = [
  { cmd: '/plan', desc: 'Toggle plan mode (read-only)' },
  { cmd: '/tasks', desc: 'List unfinished saved tasks' },
  { cmd: '/resume <id>', desc: 'Resume a saved task' },
  { cmd: '/undo', desc: 'Revert last file edit' },
  { cmd: '/clear', desc: 'Clear transcript' },
  { cmd: '/help', desc: 'Show all commands and shortcuts' },
  { cmd: '/exit', desc: 'Quit Buzzard TUI' },
];

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
    onSubmit(trimmed);
  };

  const isRunning = status === 'running';
  const showCommands = val.startsWith('/') && !val.includes(' ');
  const matchingCommands = showCommands
    ? COMMAND_HINTS.filter((c) => c.cmd.startsWith(val.toLowerCase())).slice(0, 3)
    : [];

  const divider = '─'.repeat(Math.max(10, width));

  return (
    <Box flexDirection="column" width={width}>
      {/* Autocomplete hints */}
      {matchingCommands.length > 0 && (
        <Box flexDirection="column" borderStyle="single" borderColor="cyan" paddingX={1} marginBottom={0}>
          {matchingCommands.map((c) => (
            <Box key={c.cmd} gap={2}>
              <Text bold color="cyan">{c.cmd}</Text>
              <Text dimColor>{c.desc}</Text>
            </Box>
          ))}
        </Box>
      )}

      {/* Status / Activity Line */}
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
          <Text dimColor>Plan: </Text>
          <Text color={planMode ? 'yellowBright' : 'greenBright'} bold>
            {planMode ? 'ON' : 'OFF'}
          </Text>
        </Box>
      </Box>

      {/* Input Prompt */}
      <Box width={width} marginTop={0}>
        <Text color="greenBright" bold>❯ </Text>
        <TextInput
          value={val}
          onChange={setVal}
          onSubmit={handleSubmit}
          placeholder={isRunning ? 'Task in progress... (type to queue)' : 'Ask Buzzard anything... (/help for commands)'}
        />
      </Box>

      {/* Legend / Keybinding line */}
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
          <Text color="cyanBright">[/]</Text>
          <Text dimColor>Commands</Text>
        </Box>
        <Box>
          <Text color="cyanBright">[Ctrl+C]</Text>
          <Text dimColor> Cancel / Quit</Text>
        </Box>
      </Box>
    </Box>
  );
};
