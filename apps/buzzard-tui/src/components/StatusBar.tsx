import React from 'react';
import { Box, Text } from 'ink';

interface StatusBarProps {
  planMode: boolean;
  status: string;
}

export const StatusBar: React.FC<StatusBarProps> = ({ planMode, status }) => {
  return (
    <Box
      borderStyle="single"
      borderColor="gray"
      paddingX={1}
      justifyContent="space-between"
      marginTop={1}
    >
      <Box gap={1}>
        <Text color="cyanBright">[Enter]</Text>
        <Text dimColor>Send</Text>
        <Text dimColor>│</Text>
        <Text color="cyanBright">[Tab]</Text>
        <Text dimColor>Toggle Plan ({planMode ? 'ON' : 'OFF'})</Text>
        <Text dimColor>│</Text>
        <Text color="cyanBright">[/]</Text>
        <Text dimColor>Slash Commands</Text>
        <Text dimColor>│</Text>
        <Text color="cyanBright">[Ctrl+C]</Text>
        <Text dimColor>Cancel / Quit</Text>
      </Box>

      <Box>
        <Text dimColor>Status: </Text>
        <Text color="whiteBright">{status}</Text>
      </Box>
    </Box>
  );
};
