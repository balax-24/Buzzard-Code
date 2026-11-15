import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { MessageItem, ToolEvent } from '../types.js';

interface Line {
  id: string;
  prefix?: string;
  prefixColor?: string;
  text: string;
  color?: string;
  bold?: boolean;
  dimColor?: boolean;
}

interface TranscriptProps {
  width: number;
  height: number;
  messages: MessageItem[];
  tools: ToolEvent[];
  evidenceReport?: string | null;
  scrollOffset: number; // 0 means top, positive value
  autoScroll: boolean;
}

export const Transcript: React.FC<TranscriptProps> = ({
  width,
  height,
  messages,
  tools,
  evidenceReport,
  scrollOffset,
  autoScroll,
}) => {
  if (height <= 0) return null;

  const maxLineWidth = Math.max(20, width - 2);

  // Convert all items into linear visual lines
  const allLines: Line[] = [];

  // 1. Messages
  for (const msg of messages) {
    if (msg.sender === 'user') {
      const wrapped = wrapText(msg.text, maxLineWidth - 4);
      wrapped.forEach((lineText, idx) => {
        allLines.push({
          id: `msg-${msg.id}-${idx}`,
          prefix: idx === 0 ? '❯ ' : '  ',
          prefixColor: 'greenBright',
          text: lineText,
          color: 'whiteBright',
          bold: true,
        });
      });
    } else if (msg.sender === 'system') {
      const wrapped = wrapText(msg.text, maxLineWidth - 4);
      wrapped.forEach((lineText, idx) => {
        allLines.push({
          id: `msg-${msg.id}-${idx}`,
          prefix: idx === 0 ? 'ℹ ' : '  ',
          prefixColor: 'cyan',
          text: lineText,
          dimColor: true,
        });
      });
    } else {
      // Assistant message
      const wrapped = wrapText(msg.text, maxLineWidth - 4);
      wrapped.forEach((lineText, idx) => {
        allLines.push({
          id: `msg-${msg.id}-${idx}`,
          prefix: idx === 0 ? '◆ ' : '  ',
          prefixColor: 'cyanBright',
          text: lineText,
          color: 'white',
        });
      });
    }
  }

  // 2. Tool Events
  for (let i = 0; i < tools.length; i++) {
    const t = tools[i]!;
    const isRunning = t.status === 'running';
    const isCompleted = t.status === 'completed';
    const isFailed = t.status === 'failed';

    const icon = isRunning ? '⠋ ' : isCompleted ? '✔ ' : '✖ ';
    const iconColor = isRunning ? 'yellow' : isCompleted ? 'green' : 'red';
    const durStr = t.durationMs !== undefined ? ` (${t.durationMs}ms)` : '';
    const exitStr = t.exitCode !== undefined && t.exitCode !== 0 ? ` [exit ${t.exitCode}]` : '';

    let argSummary = '';
    if (t.arguments?.command) argSummary = `: $ ${t.arguments.command}`;
    else if (t.arguments?.path) argSummary = `: ${t.arguments.path}`;
    else if (t.arguments?.query) argSummary = `: "${t.arguments.query}"`;

    const title = `${t.tool}${durStr}${exitStr}${argSummary}`;
    allLines.push({
      id: `tool-${i}-hdr`,
      prefix: icon,
      prefixColor: iconColor,
      text: title.length > maxLineWidth - 4 ? title.slice(0, maxLineWidth - 7) + '...' : title,
      color: isFailed ? 'red' : 'cyan',
      bold: isRunning,
    });

    if (t.preview) {
      const prevLines = t.preview.split('\n').slice(0, 3);
      for (let pIdx = 0; pIdx < prevLines.length; pIdx++) {
        const pLine = prevLines[pIdx]!;
        allLines.push({
          id: `tool-${i}-prev-${pIdx}`,
          prefix: '    ',
          text: pLine.length > maxLineWidth - 6 ? pLine.slice(0, maxLineWidth - 9) + '...' : pLine,
          dimColor: true,
          color: 'gray',
        });
      }
    }
  }

  // 3. Evidence Report
  if (evidenceReport) {
    allLines.push({
      id: 'ev-sep',
      text: '─'.repeat(maxLineWidth),
      dimColor: true,
    });
    const evLines = evidenceReport.split('\n');
    for (let eIdx = 0; eIdx < evLines.length; eIdx++) {
      const eLine = evLines[eIdx]!;
      const isPass = eLine.includes('exit 0') || eLine.includes('PASSED') || eLine.includes('✅');
      const isFail = eLine.includes('FAILED') || eLine.includes('exit 1') || eLine.includes('❌');
      allLines.push({
        id: `ev-${eIdx}`,
        prefix: '  ',
        text: eLine.length > maxLineWidth - 4 ? eLine.slice(0, maxLineWidth - 7) + '...' : eLine,
        color: isPass ? 'green' : isFail ? 'red' : eLine.startsWith('#') ? 'cyan' : undefined,
        bold: isPass || isFail || eLine.startsWith('#'),
      });
    }
  }

  const totalLines = allLines.length;

  // Calculate slice range
  let start = 0;
  let end = totalLines;

  if (totalLines > height) {
    if (autoScroll) {
      start = totalLines - height;
      end = totalLines;
    } else {
      const clampedOffset = Math.max(0, Math.min(scrollOffset, totalLines - height));
      start = clampedOffset;
      end = clampedOffset + height;
    }
  }

  const visibleLines = allLines.slice(start, end);

  // If there are more lines above or below, show subtle indicator
  const hasAbove = start > 0;
  const hasBelow = end < totalLines;

  return (
    <Box flexDirection="column" width={width} height={height} overflow="hidden">
      {hasAbove && (
        <Box width={width} justifyContent="center">
          <Text dimColor color="yellow">▲ [{start} lines above • PgUp to view]</Text>
        </Box>
      )}

      {visibleLines.map((line) => (
        <Box key={line.id} width={width}>
          {line.prefix && (
            <Text color={line.prefixColor} bold={line.bold}>
              {line.prefix}
            </Text>
          )}
          <Text
            color={line.color}
            bold={line.bold}
            dimColor={line.dimColor}
          >
            {line.text}
          </Text>
        </Box>
      ))}

      {hasBelow && (
        <Box width={width} justifyContent="center">
          <Text dimColor color="yellow">▼ [{totalLines - end} lines below • PgDn to scroll]</Text>
        </Box>
      )}
    </Box>
  );
};

function wrapText(text: string, maxWidth: number): string[] {
  if (!text) return [''];
  const lines: string[] = [];
  const rawLines = text.split('\n');

  for (const raw of rawLines) {
    if (raw.length <= maxWidth) {
      lines.push(raw);
    } else {
      for (let i = 0; i < raw.length; i += maxWidth) {
        lines.push(raw.slice(i, i + maxWidth));
      }
    }
  }
  return lines;
}
