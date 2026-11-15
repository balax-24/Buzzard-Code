import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import gradient from 'gradient-string';

// Official Brand Gradients for Buzzard Code & Buzzard Go
export const buzzardGradient = gradient(['#00F2FE', '#4FACFE', '#0072FF']);
export const raptorGradient = gradient(['#00F2FE', '#38EF7D']);
export const electricGradient = gradient(['#FFE000', '#00F2FE']);

// Fixed-width Official Brand Mark
export const BRAND_GLYPH = '◤⚡◢';

interface BuzzardSpinnerProps {
  active: boolean;
  label?: string;
  color?: string;
}

/**
 * Official Buzzard Raptor Strike animation.
 * Replaces Claude's spark animation during active reasoning and tool execution.
 * 
 * When active: animates glowing raptor strike frames (◤⠋◢ ... ◤⠏◢).
 * When idle: costs 0 CPU, runs 0 timers, and renders the static brand mark.
 */
export const BuzzardSpinner: React.FC<BuzzardSpinnerProps> = ({ active, label, color = 'cyanBright' }) => {
  const [frame, setFrame] = useState(0);
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => {
      setFrame((f) => (f + 1) % frames.length);
    }, 80);
    return () => clearInterval(timer);
  }, [active]);

  if (!active) {
    return (
      <Box gap={1} alignItems="center">
        <Text color="cyanBright">◤<Text color="yellowBright" bold>⚡</Text>◢</Text>
        {label && <Text dimColor>{label}</Text>}
      </Box>
    );
  }

  return (
    <Box gap={1} alignItems="center">
      <Text color="cyanBright">◤<Text color="yellowBright" bold>{frames[frame]}</Text>◢</Text>
      {label && <Text color={color} bold>{label}</Text>}
    </Box>
  );
};

interface BuzzardWordmarkProps {
  variant?: 'code' | 'go';
}

export const BuzzardWordmark: React.FC<BuzzardWordmarkProps> = ({ variant = 'code' }) => {
  const title = variant === 'go' ? 'BUZZARD GO' : 'BUZZARD CODE';
  return (
    <Box gap={1} alignItems="center">
      <Text color="cyanBright">◤<Text color="yellowBright" bold>⚡</Text>◢</Text>
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
  tokens?: number;
  cost?: number | null;
}

export const BuzzardWelcome: React.FC<BuzzardWelcomeProps> = ({
  width,
  model,
  provider,
  workspace,
  planMode,
  tokens = 0,
  cost,
}) => {
  const cardWidth = Math.min(Math.max(40, width - 4), 100);
  const costStr = cost !== undefined && cost !== null ? `$${cost.toFixed(4)}` : '$0.0000';

  return (
    <Box flexDirection="column" marginY={1} width={cardWidth}>
      {/* Brand Header Banner */}
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor="cyanBright"
        paddingX={2}
        paddingY={0}
      >
        <Box justifyContent="space-between" width="100%">
          <Box gap={1} alignItems="center">
            <Text color="cyanBright">◤<Text color="yellowBright" bold>⚡</Text>◢</Text>
            <Text bold>{buzzardGradient('BUZZARD CODE')}</Text>
            <Text color="yellowBright" bold>v2.1</Text>
            <Text dimColor>│</Text>
            <Text color="whiteBright">Autonomous Engineering Agent</Text>
          </Box>
          <Box gap={1}>
            {planMode ? (
              <Text backgroundColor="yellow" color="black" bold> PLAN MODE </Text>
            ) : (
              <Text backgroundColor="green" color="black" bold> ACT MODE </Text>
            )}
          </Box>
        </Box>

        <Text dimColor color="gray">{'─'.repeat(Math.max(20, cardWidth - 6))}</Text>

        <Box justifyContent="space-between" width="100%">
          <Box gap={1}>
            <Text dimColor>Model:</Text>
            <Text color="cyanBright" bold>{model}</Text>
            <Text dimColor>({provider})</Text>
          </Box>
          <Box gap={2}>
            <Text dimColor>Tokens: <Text color="whiteBright">{tokens.toLocaleString()}</Text></Text>
            <Text dimColor>Cost: <Text color="greenBright">{costStr}</Text></Text>
          </Box>
        </Box>

        <Box width="100%">
          <Text dimColor>Workspace: </Text>
          <Text color="whiteBright">{workspace}</Text>
        </Box>
      </Box>

      {/* Quick Reference Shortcuts */}
      <Box gap={2} marginTop={1}>
        <Text dimColor>Quick Tips:</Text>
        <Text><Text color="cyanBright" bold>[Tab]</Text> <Text dimColor>Toggle Plan Mode</Text></Text>
        <Text><Text color="cyanBright" bold>/diff</Text> <Text dimColor>Git Changes</Text></Text>
        <Text><Text color="cyanBright" bold>/cost</Text> <Text dimColor>Token Telemetry</Text></Text>
        <Text><Text color="cyanBright" bold>/help</Text> <Text dimColor>All Commands</Text></Text>
      </Box>
    </Box>
  );
};
