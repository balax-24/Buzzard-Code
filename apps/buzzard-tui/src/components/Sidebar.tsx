import React from 'react';
import { Box, Text } from 'ink';
import { TaskItem, ToolEvent } from '../types.js';

interface SidebarProps {
  width: number;
  height: number;
  tasks: TaskItem[];
  tools: ToolEvent[];
  planMode: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  width,
  height,
  tasks,
  tools,
  planMode,
}) => {
  if (width <= 0 || height <= 0) return null;

  // Track unique touched files from tool arguments
  const touchedFiles = new Set<string>();
  for (const t of tools) {
    if (t.arguments?.path) {
      touchedFiles.add(t.arguments.path.split(/[\\/]/).pop() || t.arguments.path);
    }
  }

  const filesList = Array.from(touchedFiles).slice(0, 6);

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
      <Text dimColor>{'─'.repeat(Math.max(5, width - 4))}</Text>

      {/* Mode & Safety */}
      <Box flexDirection="column" marginTop={0} marginBottom={1}>
        <Text dimColor>Safety Mode:</Text>
        <Text color={planMode ? 'yellowBright' : 'greenBright'}>
          {planMode ? '● Read-Only (Plan)' : '● Gated Execution (Act)'}
        </Text>
      </Box>

      {/* Files Modified / Inspected */}
      <Box flexDirection="column" marginBottom={1}>
        <Text dimColor>Files Touched ({touchedFiles.size}):</Text>
        {filesList.length === 0 ? (
          <Text dimColor color="gray">  (None yet)</Text>
        ) : (
          filesList.map((f, idx) => (
            <Text key={idx} color="whiteBright">  • {f}</Text>
          ))
        )}
      </Box>

      {/* Durable Tasks */}
      <Box flexDirection="column" marginBottom={1}>
        <Text dimColor>Unfinished Tasks ({tasks.length}):</Text>
        {tasks.length === 0 ? (
          <Text dimColor color="gray">  (No saved tasks)</Text>
        ) : (
          tasks.slice(0, 3).map((t) => (
            <Text key={t.taskId} color="yellow">
              {' '}[{t.taskId.slice(0, 6)}] {t.goal.slice(0, Math.max(10, width - 15))}
            </Text>
          ))
        )}
      </Box>

      <Box flexGrow={1} />

      {/* Bottom Hint */}
      <Box flexDirection="column">
        <Text dimColor>{'─'.repeat(Math.max(5, width - 4))}</Text>
        <Text dimColor color="gray">Type /help for commands</Text>
      </Box>
    </Box>
  );
};
