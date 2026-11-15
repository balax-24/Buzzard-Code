import React from 'react';
import { Box, Text, useInput } from 'ink';
import SelectInput from 'ink-select-input';
import { ApprovalRequest } from '../types.js';

interface ApprovalDialogProps {
  request: ApprovalRequest;
  onRespond: (decision: 'allow' | 'allow_session' | 'deny') => void;
}

export const ApprovalDialog: React.FC<ApprovalDialogProps> = ({ request, onRespond }) => {
  useInput((input, key) => {
    if (input === 'a' || input === 'A' || key.return) {
      onRespond('allow');
    } else if ((input === 's' || input === 'S') && request.canAllowForSession) {
      onRespond('allow_session');
    } else if (input === 'd' || input === 'D' || key.escape) {
      onRespond('deny');
    }
  });

  const items = [
    { label: '[a] Allow Once', value: 'allow' },
    ...(request.canAllowForSession
      ? [{ label: '[s] Allow for Session', value: 'allow_session' }]
      : []),
    { label: '[d] Deny', value: 'deny' },
  ];

  const handleSelect = (item: { value: string }) => {
    onRespond(item.value as 'allow' | 'allow_session' | 'deny');
  };

  const riskColor = request.riskClass === 'high' ? 'red' : 'yellow';

  return (
    <Box
      flexDirection="column"
      borderStyle="double"
      borderColor="magenta"
      paddingX={1}
      paddingY={1}
      marginY={1}
    >
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold color="magenta">
          🔒 APPROVAL REQUIRED: <Text color="cyan">{request.tool}</Text>
        </Text>
        <Text backgroundColor={riskColor} color="black" bold>
          {' '}{request.riskClass.toUpperCase()} RISK{' '}
        </Text>
      </Box>

      <Box flexDirection="column" marginBottom={1}>
        {request.arguments.command && (
          <Box>
            <Text color="yellow" bold>$ </Text>
            <Text color="whiteBright">{request.arguments.command}</Text>
          </Box>
        )}
        {request.arguments.path && (
          <Box>
            <Text dimColor>Target Path: </Text>
            <Text color="whiteBright">{request.arguments.path}</Text>
          </Box>
        )}
        {request.arguments.diff && (
          <Box flexDirection="column" marginTop={1}>
            <Text dimColor>Diff preview:</Text>
            <Text color="green">{request.arguments.diff.slice(0, 400)}</Text>
          </Box>
        )}
      </Box>

      <Text dimColor>Select decision or press [a] Allow, [s] Session, [d] Deny:</Text>
      <Box marginTop={1}>
        <SelectInput items={items} onSelect={handleSelect} />
      </Box>
    </Box>
  );
};
