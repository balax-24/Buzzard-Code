import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { BRAND_GLYPH, buzzardGradient } from './BuzzardLogo.js';

interface HeaderProps {
  width: number;
  brand?: string;
  model: string;
  provider: string;
  workspace: string;
  planMode: boolean;
  tokens?: number;
  cost?: number | null;
  status: 'idle' | 'running' | 'approval_required' | 'cancelled' | 'error';
}

export const Header: React.FC<HeaderProps> = ({
  width,
  brand = 'BUZZARD CODE',
  model,
  provider,
  workspace,
  planMode,
  tokens = 0,
  cost,
  status,
}) => {
  let statusBadge = <Text color="green">● IDLE</Text>;
  if (status === 'running') {
    statusBadge = (
      <Text color="yellowBright">
        <Spinner type="dots" /> RUNNING
      </Text>
    );
  } else if (status === 'approval_required') {
    statusBadge = <Text color="magenta" bold>🔒 APPROVAL REQUIRED</Text>;
  } else if (status === 'error') {
    statusBadge = <Text color="red">✖ ERROR</Text>;
  } else if (status === 'cancelled') {
    statusBadge = <Text color="gray">◼ CANCELLED</Text>;
  }

  const modeBadge = planMode ? (
    <Text backgroundColor="yellow" color="black" bold> PLAN MODE </Text>
  ) : (
    <Text backgroundColor="green" color="black" bold> ACT MODE </Text>
  );

  const maxPathLen = Math.max(15, width - 50);
  const shortWorkspace = workspace.length > maxPathLen
    ? '...' + workspace.slice(-maxPathLen)
    : workspace;

  const costStr = cost !== undefined && cost !== null ? `$${cost.toFixed(4)}` : '$0.0000';
  const divider = '─'.repeat(Math.max(10, width));

  return (
    <Box flexDirection="column" width={width} height={3}>
      <Box justifyContent="space-between" width={width}>
        <Box gap={1} alignItems="center">
          <Text color="yellowBright" bold>{BRAND_GLYPH}</Text>
          <Text bold>{buzzardGradient(brand)} </Text>
          <Text dimColor>│ </Text>
          <Text color="cyanBright">{model}</Text>
          <Text dimColor> ({provider})</Text>
        </Box>
        <Box gap={1}>
          {modeBadge}
          {statusBadge}
        </Box>
      </Box>

      <Box justifyContent="space-between" width={width}>
        <Box>
          <Text dimColor>📁 </Text>
          <Text color="whiteBright">{shortWorkspace}</Text>
        </Box>
        <Box gap={2}>
          <Text dimColor>Tokens: <Text color="whiteBright">{tokens.toLocaleString()}</Text></Text>
          <Text dimColor>Cost: <Text color="greenBright">{costStr}</Text></Text>
        </Box>
      </Box>

      <Text dimColor color="gray">{divider}</Text>
    </Box>
  );
};
