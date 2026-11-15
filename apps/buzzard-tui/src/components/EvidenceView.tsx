import React from 'react';
import { Box, Text } from 'ink';

interface EvidenceViewProps {
  report: string;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({ report }) => {
  if (!report) return null;

  const lines = report.split('\n');
  const isPass = report.includes('exit 0') || report.includes('PASSED') || report.includes('✅');

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor={isPass ? 'green' : 'red'}
      paddingX={1}
      marginY={1}
    >
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold color={isPass ? 'green' : 'red'}>
          {isPass ? '✔ AUTHORITATIVE EVIDENCE REPORT (PASSED)' : '✖ EVIDENCE REPORT (GATE FAILED)'}
        </Text>
      </Box>

      {lines.map((line, idx) => {
        let color: string | undefined = undefined;
        let bold = false;

        if (line.startsWith('#')) {
          color = 'cyan';
          bold = true;
        } else if (line.includes('exit 0') || line.includes('PASSED') || line.includes('passed')) {
          color = 'green';
        } else if (line.includes('FAILED') || line.includes('failed') || line.includes('exit 1')) {
          color = 'red';
          bold = true;
        } else if (line.includes('coverage:') || line.includes('Coverage:')) {
          color = 'yellow';
        }

        return (
          <Text key={idx} color={color} bold={bold}>
            {line}
          </Text>
        );
      })}
    </Box>
  );
};
