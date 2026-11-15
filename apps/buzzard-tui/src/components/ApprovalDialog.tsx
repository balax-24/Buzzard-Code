import React from 'react';
import { Box, Text, useInput } from 'ink';
import { ApprovalRequest } from '../types.js';

interface ApprovalDialogProps {
  width: number;
  request: ApprovalRequest;
  onRespond: (decision: 'allow' | 'allow_session' | 'deny') => void;
}

export const ApprovalDialog: React.FC<ApprovalDialogProps> = ({ width, request, onRespond }) => {
  useInput((input, key) => {
    if (input === 'a' || input === 'A' || key.return) {
      onRespond('allow');
    } else if ((input === 's' || input === 'S') && request.canAllowForSession) {
      onRespond('allow_session');
    } else if (input === 'd' || input === 'D' || key.escape) {
      onRespond('deny');
    }
  }, { isActive: Boolean(process.stdin.isTTY) });

  const isHigh = request.riskClass === 'high';
  const riskColor = isHigh ? 'redBright' : 'yellowBright';

  let previewText = '';
  if (request.arguments.command) {
    previewText = `$ ${request.arguments.command}`;
  } else if (request.arguments.path) {
    previewText = `Target: ${request.arguments.path}`;
  } else {
    previewText = JSON.stringify(request.arguments);
  }

  const maxLen = Math.max(20, width - 6);
  const truncatedPreview = previewText.length > maxLen
    ? previewText.slice(0, maxLen - 3) + '...'
    : previewText;

  return (
    <Box
      flexDirection="column"
      width={width}
      borderStyle="double"
      borderColor="magentaBright"
      paddingX={1}
      marginY={0}
    >
      <Box justifyContent="space-between" width={width - 4}>
        <Text bold color="magentaBright">
          🔒 APPROVAL REQUIRED: <Text color="cyanBright">{request.tool}</Text>
        </Text>
        <Text backgroundColor={isHigh ? 'red' : 'yellow'} color="black" bold>
          {' '}{request.riskClass.toUpperCase()} RISK{' '}
        </Text>
      </Box>

      <Box marginY={0}>
        <Text color="yellowBright" bold>{truncatedPreview}</Text>
      </Box>

      <Box justifyContent="space-between" marginTop={1}>
        <Box gap={2}>
          <Text color="greenBright" bold>[a] Allow Once</Text>
          {request.canAllowForSession && (
            <Text color="cyanBright" bold>[s] Allow for Session</Text>
          )}
          <Text color="redBright" bold>[d] Deny</Text>
        </Box>
        <Text dimColor color="gray">Press a / s / d or Enter/Esc</Text>
      </Box>
    </Box>
  );
};
