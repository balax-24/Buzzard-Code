import React from 'react';
import { Box, Text } from 'ink';
import gradient from 'gradient-string';

// Official Brand Gradients for Buzzard Code & Buzzard Go
export const buzzardGradient = gradient(['#00F2FE', '#4FACFE', '#0072FF']);
export const raptorGradient = gradient(['#00F2FE', '#38EF7D']);
export const electricGradient = gradient(['#FFE000', '#00F2FE']);

// Fixed-width Official Brand Mark
export const BRAND_GLYPH = '◤⚡◢';

interface BuzzardWordmarkProps {
  variant?: 'code' | 'go';
}

export const BuzzardWordmark: React.FC<BuzzardWordmarkProps> = ({ variant = 'code' }) => {
  const title = variant === 'go' ? 'BUZZARD GO' : 'BUZZARD CODE';
  return (
    <Box gap={1} alignItems="center">
      <Text color="yellowBright" bold>{BRAND_GLYPH}</Text>
      <Text bold>{buzzardGradient(title)}</Text>
    </Box>
  );
};

interface BuzzardWelcomeProps {
  width: number;
  model: string;
  provider: string;
  workspace: string;
  planMode: boolean;
}

export const BuzzardWelcome: React.FC<BuzzardWelcomeProps> = ({
  width,
  model,
  provider,
  workspace,
  planMode,
}) => {
  const innerWidth = Math.max(30, width - 4);
  const isCompact = width < 80;

  return (
    <Box flexDirection="column" paddingX={1} marginY={0}>
      {/* Official Buzzard Brand Logo Card */}
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor="cyanBright"
        paddingX={2}
        paddingY={0}
        marginBottom={1}
        width={innerWidth}
      >
        {!isCompact ? (
          <Box flexDirection="row" alignItems="center" gap={3} marginY={0}>
            {/* Geometric ASCII Raptor Emblem */}
            <Box flexDirection="column">
              <Text color="cyanBright" bold>{'      /\\   '}<Text color="yellowBright">⚡</Text>{'   /\\  '}</Text>
              <Text color="cyanBright" bold>{'     /  \\  /\\  /  \\ '}</Text>
              <Text color="cyanBright" bold>{'    <    \\//\\/    >'}</Text>
              <Text color="cyanBright" bold>{'     \\___/ \\/ \\___/ '}</Text>
            </Box>

            {/* Brand Typography & Credentials */}
            <Box flexDirection="column">
              <Box gap={1}>
                <Text bold>{buzzardGradient('BUZZARD CODE')}</Text>
                <Text color="yellowBright" bold>v2.1</Text>
                <Text dimColor>│</Text>
                <Text color="greenBright" bold>BUZZARD GO</Text>
              </Box>
              <Text color="whiteBright">Autonomous Security & Software Engineering Agent</Text>
              <Text dimColor color="gray">The model proposes, authoritative code decides.</Text>
            </Box>
          </Box>
        ) : (
          <Box flexDirection="column">
            <Box gap={1}>
              <Text color="yellowBright" bold>{BRAND_GLYPH}</Text>
              <Text bold>{buzzardGradient('BUZZARD CODE / BUZZARD GO')}</Text>
              <Text dimColor>v2.1</Text>
            </Box>
            <Text dimColor>Autonomous Security & Software Engineering Agent</Text>
          </Box>
        )}

        <Text dimColor color="gray">{'─'.repeat(Math.max(10, innerWidth - 6))}</Text>

        {/* Runtime Environment Context */}
        <Box justifyContent="space-between" width={innerWidth - 6}>
          <Box gap={1}>
            <Text dimColor>Model:</Text>
            <Text color="cyanBright" bold>{model}</Text>
            <Text dimColor>({provider})</Text>
          </Box>
          <Box gap={1}>
            <Text dimColor>Safety Mode:</Text>
            <Text color={planMode ? 'yellowBright' : 'greenBright'} bold>
              {planMode ? 'PLAN MODE (Read-Only)' : 'ACT MODE (Authoritative Execution)'}
            </Text>
          </Box>
        </Box>

        <Box width={innerWidth - 6}>
          <Text dimColor>Workspace: </Text>
          <Text color="whiteBright">{workspace}</Text>
        </Box>
      </Box>

      {/* Quick Navigation & Keyboard Shortcuts */}
      <Box flexDirection="column" marginBottom={1}>
        <Text bold color="yellowBright">Fast Commands & Shortcuts:</Text>
        <Box gap={1}>
          <Text color="cyanBright" bold>[Tab]</Text>
          <Text color="white">Toggle Plan Mode (safe read-only inspection)</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright" bold>/diff</Text>
          <Text color="white">Live Git Diff</Text>
        </Box>
        <Box gap={1}>
          <Text color="cyanBright" bold>/tasks</Text>
          <Text color="white">Durable task manager</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright" bold>/undo</Text>
          <Text color="white">Rollback last edit</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright" bold>/doctor</Text>
          <Text color="white">System health diagnostics</Text>
        </Box>
        <Box gap={1}>
          <Text color="cyanBright" bold>/help</Text>
          <Text color="white">Show all commands</Text>
          <Text dimColor>│</Text>
          <Text color="cyanBright" bold>[Ctrl+C]</Text>
          <Text color="white">Cancel running task / exit</Text>
        </Box>
      </Box>

      {/* Starter Prompts */}
      <Box flexDirection="column">
        <Text dimColor color="gray">Suggested prompts:</Text>
        <Text dimColor>  • "Review git changes with /diff and fix security issues"</Text>
        <Text dimColor>  • "Run full pytest suite and analyze failures"</Text>
        <Text dimColor>  • "Explain the architecture and data flow of this repo"</Text>
      </Box>
    </Box>
  );
};
