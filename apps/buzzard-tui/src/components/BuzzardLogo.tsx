import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import gradient from 'gradient-string';

// High-impact brand gradients
export const cyanGradient = gradient(['#00F2FE', '#4FACFE', '#0072FF']);
export const buzzardGradient = gradient(['#00F2FE', '#4FACFE', '#7B2CBF', '#0072FF']);
export const electricGradient = gradient(['#FFE000', '#799F0C', '#00F2FE']);

// Animated Falcon Morphing Frames for Buzzard Brand
const FALCON_FRAMES = [
  '⟨⠋ 🦅 ⠙⟩',
  '⟨⠙ ⚡ ⠚⟩',
  '⟨⠹ ◈ ⠒⟩',
  '⟨⠸ 🦅 ⠂⟩',
  '⟨⠼ ⚡ ⠄⟩',
  '⟨⠴ ◈ ⠤⟩',
  '⟨⠦ 🦅 ⠠⟩',
  '⟨⠧ ⚡ ⠐⟩',
];

const WING_FRAMES = [
  '\\ v /',
  '( \\ / )',
  '// ⚡ \\\\',
  '⟨ 🦅 ⟩',
  '\\\\ ⚡ //',
  '( •_• )',
];

interface BuzzardSpinnerProps {
  mode?: 'falcon' | 'wings' | 'spark';
  active?: boolean;
}

export const BuzzardSpinner: React.FC<BuzzardSpinnerProps> = ({
  mode = 'falcon',
  active = true,
}) => {
  const [frameIndex, setFrameIndex] = useState(0);

  useEffect(() => {
    if (!active) return;
    const interval = setInterval(() => {
      setFrameIndex((prev) => (prev + 1) % (mode === 'wings' ? WING_FRAMES.length : FALCON_FRAMES.length));
    }, 110);
    return () => clearInterval(interval);
  }, [active, mode]);

  if (!active) {
    return <Text color="cyanBright">⟨🦅⟩</Text>;
  }

  const glyph = mode === 'wings' ? WING_FRAMES[frameIndex] : FALCON_FRAMES[frameIndex];
  return <Text color="cyanBright" bold>{glyph}</Text>;
};

interface BuzzardLogoProps {
  variant?: 'code' | 'go';
  withSpinner?: boolean;
}

export const BuzzardLogo: React.FC<BuzzardLogoProps> = ({
  variant = 'code',
  withSpinner = true,
}) => {
  const brandName = variant === 'go' ? 'BUZZARD GO' : 'BUZZARD CODE';

  return (
    <Box gap={1} alignItems="center">
      {withSpinner && <BuzzardSpinner mode="falcon" active={true} />}
      <Text bold>{buzzardGradient(brandName)}</Text>
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
  const isCompact = width < 90;
  const innerWidth = Math.max(20, width - 4);

  const banner = [
    ' ____  _   _ _____ _____    _    ____  ____       ____ ___  ____  _____ ',
    '| __ )| | | |__  /__  /    / \\  |  _ \\|  _ \\     / ___/ _ \\|  _ \\| ____|',
    '|  _ \\| | | | / /  / /    / _ \\ | |_) | | | |   | |  | | | | | | |  _|  ',
    '| |_) | |_| |/ /_ / /_   / ___ \\|  _ <| |_| |   | |__| |_| | |_| | |___ ',
    '|____/ \\___//____/____| /_/   \\_\\_| \\_\\____/     \\____\\___/|____/|_____|',
  ];

  const compactBanner = [
    '⚡ BUZZARD CODE  (BUZZARD GO ENGINE v2.1)',
    '   Autonomous Full-Stack Security & Software Agent',
  ];

  return (
    <Box flexDirection="column" paddingX={1} marginY={0}>
      {/* Brand Hero Display */}
      <Box flexDirection="column" marginBottom={1}>
        {isCompact ? (
          compactBanner.map((line, idx) => (
            <Text key={idx} bold color="cyanBright">
              {line}
            </Text>
          ))
        ) : (
          banner.map((line, idx) => (
            <Text key={idx} bold>
              {buzzardGradient(line)}
            </Text>
          ))
        )}
      </Box>

      {/* Welcome Card & Metadata */}
      <Box
        flexDirection="column"
        borderStyle="round"
        borderColor="cyanBright"
        paddingX={1}
        marginBottom={1}
        width={innerWidth}
      >
        <Box justifyContent="space-between" width={innerWidth - 4}>
          <Box gap={1}>
            <BuzzardSpinner mode="falcon" active={true} />
            <Text bold color="whiteBright">Welcome to Buzzard Code</Text>
            <Text dimColor>v2.1</Text>
          </Box>
          <Box gap={1}>
            <Text dimColor>Engine: </Text>
            <Text color="cyanBright" bold>Buzzard Go</Text>
          </Box>
        </Box>

        <Text dimColor color="gray">{'─'.repeat(innerWidth - 4)}</Text>

        <Box justifyContent="space-between" width={innerWidth - 4}>
          <Text dimColor>Active Model: <Text color="yellowBright" bold>{model}</Text> ({provider})</Text>
          <Text dimColor>Mode: <Text color={planMode ? 'yellowBright' : 'greenBright'} bold>{planMode ? 'PLAN (Read-Only)' : 'ACT (Full Toolchain)'}</Text></Text>
        </Box>

        <Box width={innerWidth - 4}>
          <Text dimColor>Workspace: <Text color="whiteBright">{workspace}</Text></Text>
        </Box>
      </Box>

      {/* Quick Start Guide */}
      <Box flexDirection="column" marginBottom={1}>
        <Text bold color="yellowBright">Quick Commands & Shortcuts:</Text>
        <Box gap={1} marginTop={0}>
          <Text color="cyanBright" bold>[Tab]</Text>
          <Text color="white">Toggle Plan Mode (safe read-only inspection)</Text>
        </Box>
        <Box gap={1}>
          <Text color="cyanBright" bold>/diff</Text>
          <Text color="white">Open interactive unified git diff inspector</Text>
        </Box>
        <Box gap={1}>
          <Text color="cyanBright" bold>/tasks</Text>
          <Text color="white">List durable unfinished tasks across sessions</Text>
        </Box>
        <Box gap={1}>
          <Text color="cyanBright" bold>/undo</Text>
          <Text color="white">Instantly rollback the last applied file edit</Text>
        </Box>
        <Box gap={1}>
          <Text color="cyanBright" bold>/help</Text>
          <Text color="white">Show complete command and shortcut reference</Text>
        </Box>
      </Box>

      {/* Suggested Starters */}
      <Box flexDirection="column">
        <Text dimColor color="gray">Suggested tasks to try:</Text>
        <Text dimColor>  • "Review recent git diff and check for bugs"</Text>
        <Text dimColor>  • "Run full pytest suite and analyze test failures"</Text>
        <Text dimColor>  • "Explain the architecture of this project"</Text>
      </Box>
    </Box>
  );
};
