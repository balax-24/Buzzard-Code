import React from 'react';
import { Box, Text } from 'ink';
import { MessageItem, ToolEvent } from '../types.js';
import { ToolCard } from './ToolCard.js';
import { EvidenceView } from './EvidenceView.js';

interface ChatFeedProps {
  messages: MessageItem[];
  tools: ToolEvent[];
  evidenceReport?: string;
}

export const ChatFeed: React.FC<ChatFeedProps> = ({ messages, tools, evidenceReport }) => {
  return (
    <Box flexDirection="column" marginY={1}>
      {messages.map((msg) => {
        if (msg.sender === 'user') {
          return (
            <Box key={msg.id} marginY={0}>
              <Text bold color="green">❯ </Text>
              <Text color="whiteBright">{msg.text}</Text>
            </Box>
          );
        } else if (msg.sender === 'system') {
          return (
            <Box key={msg.id} marginY={0}>
              <Text dimColor>ℹ {msg.text}</Text>
            </Box>
          );
        } else {
          return (
            <Box key={msg.id} flexDirection="column" marginY={0}>
              <Box>
                <Text bold color="cyan">◆ </Text>
                <Text color="whiteBright">{msg.text}</Text>
              </Box>
            </Box>
          );
        }
      })}

      {tools.map((t, idx) => (
        <ToolCard key={`${t.tool}-${idx}`} event={t} />
      ))}

      {evidenceReport ? <EvidenceView report={evidenceReport} /> : null}
    </Box>
  );
};
