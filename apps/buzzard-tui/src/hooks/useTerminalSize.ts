import { useState, useEffect } from 'react';

export interface TerminalSize {
  columns: number;
  rows: number;
}

export function useTerminalSize(): TerminalSize {
  const [size, setSize] = useState<TerminalSize>(() => ({
    columns: Math.max(40, process.stdout.columns || 100),
    rows: Math.max(15, process.stdout.rows || 30),
  }));

  useEffect(() => {
    const handleResize = () => {
      // Clear screen on geometry change
      process.stdout.write('\x1b[2J\x1b[H');
      setSize({
        columns: Math.max(40, process.stdout.columns || 100),
        rows: Math.max(15, process.stdout.rows || 30),
      });
    };

    process.stdout.on('resize', handleResize);
    return () => {
      process.stdout.off('resize', handleResize);
    };
  }, []);

  return size;
}
