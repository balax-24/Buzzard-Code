import React from 'react';
import { Box, Text } from 'ink';
import { TaskItem, ToolEvent } from '../types.js';
import { GitSummary } from '../workspace/gitStatus.js';

interface SidebarProps {
  width: number;
  height: number;
  tasks: TaskItem[];
  tools: ToolEvent[];
  planMode: boolean;
  gitSummary?: GitSummary;
}

export const Sidebar: React.FC<SidebarProps> = ({
  width,
  height,
  tasks,
  tools,
  planMode,
  gitSummary,
}) => {
  if (width <= 0 || height <= 0) return null;

  const innerWidth = Math.max(10, width - 4);

  return (
    <Box
      flexDirection="column"
      width={width}
      height={height}
      borderStyle="single"
      borderColor="gray"
      paddingX={1}
      overflow="hidden"
    >
      <Text bold color="cyanBright">SESSION INSPECTOR</Text>
      <Text dimColor>{'─'.repeat(innerWidth)}</Text>

      {/* Safety & Mode */}
      <Box flexDirection="column" marginBottom={1}>
        <Text dimColor>Safety Mode:</Text>
        <Text color={planMode ? 'yellowBright' : 'greenBright'} bold>
          {planMode ? '● Read-Only (Plan Mode)' : '● Gated Execution (Act)'}
        </Text>
      </Box>

      {/* Git Changes (Claude Code /diff pane aesthetic) */}
      <Box flexDirection="column" marginBottom={1}>
        <Box justifyContent="space-between" width={innerWidth}>
          <Text dimColor>Git: <Text color="whiteBright">{gitSummary?.branch || 'none'}</Text></Text>
          {gitSummary && (gitSummary.totalInsertions > 0 || gitSummary.totalDeletions > 0) && (
            <Text>
              <Text color="green">+{gitSummary.totalInsertions} </Text>
              <Text color="red">-{gitSummary.totalDeletions}</Text>
            </Text>
          )}
        </Box>

        {(!gitSummary || gitSummary.changes.length === 0) ? (
          <Text dimColor color="gray">  (Clean working tree)</Text>
        ) : (
          gitSummary.changes.slice(0, 5).map((c, idx) => {
            const letter = c.status === 'added' ? 'A' : c.status === 'deleted' ? 'D' : c.status === 'untracked' ? '?' : 'M';
            const color = c.status === 'added' ? 'green' : c.status === 'deleted' ? 'red' : c.status === 'untracked' ? 'gray' : 'yellow';
            const shortName = c.path.split(/[\\/]/).pop() || c.path;
            const diffStats = c.insertions !== undefined || c.deletions !== undefined
              ? ` (+${c.insertions || 0}/-${c.deletions || 0})`
              : '';
            return (
              <Box key={idx} width={innerWidth} justifyContent="space-between">
                <Box gap={1}>
                  <Text color={color} bold>{letter}</Text>
                  <Text color="whiteBright">{shortName.slice(0, innerWidth - 14)}</Text>
                </Box>
                <Text dimColor color="gray">{diffStats}</Text>
              </Box>
            );
          })
        )}
      </Box>

      {/* Durable Long-Horizon Tasks */}
      <Box flexDirection="column" marginBottom={1}>
        <Text dimColor>Durable Tasks ({tasks.length}):</Text>
        {tasks.length === 0 ? (
          <Text dimColor color="gray">  (No saved tasks)</Text>
        ) : (
          tasks.slice(0, 3).map((t) => (
            <Text key={t.taskId} color="yellow">
              {' '}[{t.taskId.slice(0, 6)}] {t.goal.slice(0, innerWidth - 10)}
            </Text>
          ))
        )}
      </Box>

      <Box flexGrow={1} />

      {/* Footer shortcut hints */}
      <Box flexDirection="column">
        <Text dimColor>{'─'.repeat(innerWidth)}</Text>
        <Text dimColor color="gray">Type /diff to inspect hunks</Text>
        <Text dimColor color="gray">Type /help for commands</Text>
      </Box>
    </Box>
  );
};
