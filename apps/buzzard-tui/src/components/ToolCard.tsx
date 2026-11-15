import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { ToolEvent } from '../types.js';

interface ToolCardProps {
  event: ToolEvent;
}

export const ToolCard: React.FC<ToolCardProps> = ({ event }) => {
  const isRunning = event.status === 'running';
  const isCompleted = event.status === 'completed';
  const isFailed = event.status === 'failed';

  const borderColor = isRunning ? 'yellow' : isCompleted ? 'green' : 'red';
  const icon = isRunning ? (
    <Text color="yellow"><Spinner type="dots" /> </Text>
  ) : isCompleted ? (
    <Text color="green">✔ </Text>
  ) : (
    <Text color="red">✖ </Text>
  );

  let formattedArgs = '';
  if (event.arguments && Object.keys(event.arguments).length > 0) {
    if (event.arguments.command) {
      formattedArgs = `$ ${event.arguments.command}`;
    } else if (event.arguments.path) {
      formattedArgs = event.arguments.path;
    } else if (event.arguments.query) {
      formattedArgs = `"${event.arguments.query}"`;
    } else {
      formattedArgs = JSON.stringify(event.arguments).slice(0, 80);
    }
  }

  const durationStr = event.durationMs !== undefined ? `${event.durationMs}ms` : '';
  const exitStr = event.exitCode !== undefined ? `exit ${event.exitCode}` : '';

  return (
    <Box
      flexDirection="column"
      borderStyle="single"
      borderColor={borderColor}
      paddingX={1}
      marginY={0}
    >
      <Box justifyContent="space-between">
        <Box>
          {icon}
          <Text bold color="cyan">{event.tool} </Text>
          {formattedArgs ? <Text dimColor>{formattedArgs}</Text> : null}
        </Box>
        <Box gap={1}>
          {durationStr ? <Text dimColor>{durationStr}</Text> : null}
          {exitStr ? <Text color={event.exitCode === 0 ? 'green' : 'red'}>{exitStr}</Text> : null}
        </Box>
      </Box>

      {event.preview ? (
        <Box marginTop={0} paddingLeft={2}>
          <Text color="gray">
            {event.preview.length > 300 ? event.preview.slice(0, 300) + '...' : event.preview}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
};
