import React from 'react';
import { Box, Text } from 'ink';
import gradient from 'gradient-string';

interface HeaderProps {
  model: string;
  provider: string;
  workspace: string;
  planMode: boolean;
  tokens?: number;
  cost?: number | null;
  status: 'idle' | 'running' | 'approval_required' | 'cancelled' | 'error';
}

const buzzardGradient = gradient(['#00F2FE', '#4FACFE', '#0072FF']);

export const Header: React.FC<HeaderProps> = ({
  model,
  provider,
  workspace,
  planMode,
  tokens = 0,
  cost,
  status,
}) => {
  const shortWorkspace = workspace.length > 40 ? '...' + workspace.slice(-37) : workspace;

  let statusBadge = <Text color="green">● IDLE</Text>;
  if (status === 'running') {
    statusBadge = <Text color="yellow">⚡ RUNNING</Text>;
  } else if (status === 'approval_required') {
    statusBadge = <Text color="magenta" bold>🔒 APPROVAL REQUIRED</Text>;
  } else if (status === 'error') {
    statusBadge = <Text color="red">✖ ERROR</Text>;
  } else if (status === 'cancelled') {
    statusBadge = <Text color="gray">◼ CANCELLED</Text>;
  }

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1} marginBottom={1}>
      <Box justifyContent="space-between">
        <Box>
          <Text bold>{buzzardGradient('⚡ BUZZARD CODE')} </Text>
          <Text dimColor>│ </Text>
          <Text color="cyan">{provider}/{model}</Text>
        </Box>
        <Box gap={1}>
          {planMode ? (
            <Text backgroundColor="yellow" color="black" bold> PLAN MODE </Text>
          ) : (
            <Text backgroundColor="green" color="black" bold> ACT MODE </Text>
          )}
          {statusBadge}
        </Box>
      </Box>

      <Box justifyContent="space-between" marginTop={0}>
        <Box>
          <Text dimColor>Workspace: </Text>
          <Text color="whiteBright">{shortWorkspace}</Text>
        </Box>
        <Box gap={2}>
          <Text dimColor>Tokens: <Text color="whiteBright">{tokens.toLocaleString()}</Text></Text>
          {cost !== undefined && cost !== null && (
            <Text dimColor>Cost: <Text color="greenBright">${cost.toFixed(4)}</Text></Text>
          )}
        </Box>
      </Box>
    </Box>
  );
};
