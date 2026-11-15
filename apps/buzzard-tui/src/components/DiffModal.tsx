import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';

interface DiffModalProps {
  width: number;
  height: number;
  diffText: string;
  onClose: () => void;
}

export const DiffModal: React.FC<DiffModalProps> = ({
  width,
  height,
  diffText,
  onClose,
}) => {
  const [scrollOffset, setScrollOffset] = useState(0);

  const lines = diffText ? diffText.split('\n') : ['(No uncommitted git changes in workspace)'];
  const viewHeight = Math.max(5, height - 4);

  useInput((input, key) => {
    if (key.escape || input === 'q' || input === 'Q') {
      onClose();
      return;
    }
    if (key.pageUp || key.upArrow) {
      setScrollOffset((prev) => Math.max(0, prev - 5));
      return;
    }
    if (key.pageDown || key.downArrow) {
      setScrollOffset((prev) => Math.min(Math.max(0, lines.length - viewHeight), prev + 5));
      return;
    }
  }, { isActive: Boolean(process.stdin.isTTY) });

  const visibleLines = lines.slice(scrollOffset, scrollOffset + viewHeight);
  const maxLineLen = Math.max(20, width - 6);

  return (
    <Box
      flexDirection="column"
      width={width}
      height={height}
      borderStyle="double"
      borderColor="greenBright"
      paddingX={1}
      overflow="hidden"
    >
      <Box justifyContent="space-between" width={width - 4} marginBottom={1}>
        <Text bold color="greenBright">
          📄 GIT DIFF INSPECTOR ({lines.length} lines)
        </Text>
        <Text dimColor color="gray">
          [PgUp/PgDn/Arrows] Scroll • [q/Esc] Close
        </Text>
      </Box>

      <Box flexDirection="column" width={width - 4} height={viewHeight} overflow="hidden">
        {visibleLines.map((line, idx) => {
          let color: string | undefined = undefined;
          let bold = false;

          if (line.startsWith('+') && !line.startsWith('+++')) {
            color = 'green';
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            color = 'red';
          } else if (line.startsWith('@@')) {
            color = 'cyan';
            bold = true;
          } else if (line.startsWith('diff --git')) {
            color = 'yellow';
            bold = true;
          }

          const truncated = line.length > maxLineLen ? line.slice(0, maxLineLen - 3) + '...' : line;

          return (
            <Text key={idx} color={color} bold={bold}>
              {truncated}
            </Text>
          );
        })}
      </Box>

      <Box justifyContent="space-between" width={width - 4} marginTop={0}>
        <Text dimColor color="gray">
          Showing lines {scrollOffset + 1} - {Math.min(lines.length, scrollOffset + viewHeight)} of {lines.length}
        </Text>
        <Text color="yellowBright">[Esc] Return to chat</Text>
      </Box>
    </Box>
  );
};
