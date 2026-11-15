import React from 'react';
import { Box, Text } from 'ink';

export interface CommandItem {
  cmd: string;
  args?: string;
  description: string;
  category: 'workflow' | 'inspection' | 'system';
}

export const SLASH_COMMANDS: CommandItem[] = [
  { cmd: '/diff', description: 'Show uncommitted file diffs (Claude Code /diff pane)', category: 'inspection' },
  { cmd: '/plan', args: '[on|off]', description: 'Toggle read-only plan mode (blocks edits/commands)', category: 'workflow' },
  { cmd: '/impact', args: '<files...>', description: 'Simulate blast radius, dependent callers, and risk tier', category: 'inspection' },
  { cmd: '/tests', args: '[files...]', description: 'Discover priority targeted tests using AST memory graph', category: 'inspection' },
  { cmd: '/tasks', description: 'List unfinished durable tasks for this workspace', category: 'workflow' },
  { cmd: '/resume', args: '<taskId>', description: 'Resume an interrupted durable task from disk', category: 'workflow' },
  { cmd: '/undo', description: 'Revert the last applied file edit', category: 'workflow' },
  { cmd: '/cost', description: 'Display token accounting and session cost breakdown', category: 'inspection' },
  { cmd: '/model', args: '[name]', description: 'Display or switch active model and provider routing', category: 'inspection' },
  { cmd: '/doctor', description: 'Run complete environment, security, and tool diagnostics', category: 'system' },
  { cmd: '/init', description: 'Analyze workspace architecture and generate context summary', category: 'system' },
  { cmd: '/clear', description: 'Clear terminal conversation transcript', category: 'system' },
  { cmd: '/help', description: 'Show complete command and shortcut reference', category: 'system' },
  { cmd: '/exit', description: 'Gracefully shutdown and exit TUI', category: 'system' },
];

interface CommandPaletteProps {
  width: number;
  filterText: string;
  selectedIndex: number;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  width,
  filterText,
  selectedIndex,
}) => {
  const query = filterText.toLowerCase();
  const filtered = SLASH_COMMANDS.filter((c) => c.cmd.startsWith(query)).slice(0, 5);

  if (filtered.length === 0) return null;

  return (
    <Box
      flexDirection="column"
      width={width}
      borderStyle="round"
      borderColor="cyanBright"
      paddingX={1}
      marginY={0}
    >
      <Box justifyContent="space-between" width={width - 4} marginBottom={0}>
        <Text bold color="cyanBright">SLASH COMMANDS</Text>
        <Text dimColor color="gray">[Tab] to complete • [Enter] to run</Text>
      </Box>

      {filtered.map((item, idx) => {
        const isSelected = idx === selectedIndex;
        return (
          <Box key={item.cmd} width={width - 4} justifyContent="space-between">
            <Box gap={1}>
              <Text color={isSelected ? 'yellowBright' : 'cyanBright'} bold>
                {isSelected ? '❯ ' : '  '}{item.cmd}
              </Text>
              {item.args && <Text dimColor>{item.args}</Text>}
            </Box>
            <Text color={isSelected ? 'whiteBright' : 'gray'}>
              {item.description}
            </Text>
          </Box>
        );
      })}
    </Box>
  );
};
