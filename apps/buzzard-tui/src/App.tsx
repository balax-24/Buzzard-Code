import React, { useState, useEffect, useRef } from 'react';
import { Box, useApp, useInput } from 'ink';
import { RuntimeClient } from './client.js';
import { useTerminalSize } from './hooks/useTerminalSize.js';
import { Header } from './components/Header.js';
import { Transcript } from './components/Transcript.js';
import { Sidebar } from './components/Sidebar.js';
import { Composer } from './components/Composer.js';
import { ApprovalDialog } from './components/ApprovalDialog.js';
import {
  MessageItem,
  ToolEvent,
  ApprovalRequest,
  InitializeResult,
  TaskItem,
} from './types.js';

interface AppProps {
  workspace: string;
}

export const App: React.FC<AppProps> = ({ workspace }) => {
  const { exit } = useApp();
  const { columns, rows } = useTerminalSize();

  const [initData, setInitData] = useState<InitializeResult | null>(null);
  const [client, setClient] = useState<RuntimeClient | null>(null);
  const [status, setStatus] = useState<'idle' | 'running' | 'approval_required' | 'cancelled' | 'error'>('idle');
  const [statusText, setStatusText] = useState('Connecting to Buzzard Engine...');
  const [planMode, setPlanMode] = useState(false);
  const [tokens, setTokens] = useState(0);
  const [cost, setCost] = useState<number | null>(null);

  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [tools, setTools] = useState<ToolEvent[]>([]);
  const [tasks, setTasks] = useState<TaskItem[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [evidenceReport, setEvidenceReport] = useState<string | null>(null);

  const [scrollOffset, setScrollOffset] = useState<number>(0);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);

  const streamingRef = useRef<string>('');

  useEffect(() => {
    const runtime = new RuntimeClient(workspace);

    runtime.setEvents({
      onDelta: (text) => {
        streamingRef.current += text;
        setAutoScroll(true);
        setMessages((prev) => {
          const last = prev[prev.length - 1];
          if (last && last.sender === 'assistant' && last.isStreaming) {
            return [
              ...prev.slice(0, -1),
              { ...last, text: streamingRef.current },
            ];
          }
          return [
            ...prev,
            {
              id: Date.now().toString(),
              sender: 'assistant',
              text: streamingRef.current,
              timestamp: new Date().toLocaleTimeString(),
              isStreaming: true,
            },
          ];
        });
      },

      onToolStart: (tool) => {
        setStatus('running');
        setStatusText(`Running ${tool.tool}...`);
        setAutoScroll(true);
        setTools((prev) => [...prev, tool]);
      },

      onToolEnd: (tool) => {
        setAutoScroll(true);
        setTools((prev) =>
          prev.map((t) => (t.tool === tool.tool && t.status === 'running' ? tool : t))
        );
      },

      onApprovalRequest: (req) => {
        setStatus('approval_required');
        setStatusText(`Approval needed: ${req.tool}`);
        setPendingApproval(req);
      },

      onEvidenceReport: (report) => {
        setEvidenceReport(report);
        setAutoScroll(true);
      },

      onRunFinished: (res) => {
        setStatus(res.status === 'completed' ? 'idle' : res.status === 'cancelled' ? 'cancelled' : 'error');
        setStatusText(res.status === 'completed' ? 'Ready' : `Task finished (${res.status})`);
        streamingRef.current = '';
        setAutoScroll(true);

        if (res.metrics) {
          if (res.metrics.inputTokens || res.metrics.outputTokens) {
            setTokens((prev) => prev + (res.metrics?.inputTokens || 0) + (res.metrics?.outputTokens || 0));
          }
          if (res.metrics.costUsd) {
            setCost((prev) => (prev || 0) + (res.metrics?.costUsd || 0));
          }
        }

        setMessages((prev) =>
          prev.map((m) => (m.isStreaming ? { ...m, isStreaming: false } : m))
        );

        // Refresh task list
        runtime.listTasks().then((r) => setTasks(r.tasks)).catch(() => {});
      },

      onError: (err) => {
        setStatus('error');
        setStatusText(`Engine Error: ${err.message}`);
      },

      onExit: () => {
        setStatusText('Engine disconnected');
      },
    });

    runtime
      .start()
      .then((info) => {
        setInitData(info);
        setClient(runtime);
        setStatus('idle');
        setStatusText('Ready');
        setMessages([
          {
            id: 'init',
            sender: 'system',
            text: `Connected to Buzzard Engine 1.0 (${info.provider}/${info.model})`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
        runtime.listTasks().then((r) => setTasks(r.tasks)).catch(() => {});
      })
      .catch((err) => {
        setStatus('error');
        setStatusText(`Connection failed: ${err.message}`);
      });

    return () => {
      runtime.stop().catch(() => {});
    };
  }, [workspace]);

  useInput((input, key) => {
    // Ctrl+C handling
    if (key.ctrl && input === 'c') {
      if (status === 'running' && client) {
        client.cancelRun().catch(() => {});
        setStatus('cancelled');
        setStatusText('Cancelling current task...');
        return;
      }
      if (client) client.stop();
      exit();
      return;
    }

    // Tab key toggles Plan Mode
    if (key.tab && !pendingApproval && client) {
      const nextMode = !planMode;
      setPlanMode(nextMode);
      client.setPlanMode(nextMode).catch(() => {});
      return;
    }
  });

  const handleApprovalRespond = async (decision: 'allow' | 'allow_session' | 'deny') => {
    if (!pendingApproval || !client) return;
    const reqId = pendingApproval.requestId;
    setPendingApproval(null);
    setStatus('running');
    setStatusText(`Approved: ${decision}`);
    await client.respondApproval(reqId, decision).catch(() => {});
  };

  const handleCommandSubmit = async (val: string) => {
    const trimmed = val.trim();
    if (!trimmed || !client) return;

    if (trimmed.startsWith('/')) {
      const parts = trimmed.split(' ');
      const cmd = parts[0]?.toLowerCase();
      const arg = parts.slice(1).join(' ');

      if (cmd === '/plan') {
        const nextMode = arg === 'off' ? false : arg === 'on' ? true : !planMode;
        setPlanMode(nextMode);
        await client.setPlanMode(nextMode);
        setMessages((prev) => [
          ...prev,
          { id: Date.now().toString(), sender: 'system', text: `Plan mode is now ${nextMode ? 'ON' : 'OFF'}`, timestamp: new Date().toLocaleTimeString() },
        ]);
        return;
      }

      if (cmd === '/clear') {
        setMessages([]);
        setTools([]);
        setEvidenceReport(null);
        return;
      }

      if (cmd === '/tasks') {
        const { tasks: currentTasks } = await client.listTasks();
        setTasks(currentTasks);
        const text = currentTasks.length === 0
          ? 'No unfinished tasks in this workspace.'
          : 'Saved unfinished tasks:\n' + currentTasks.map((t) => `  • [${t.taskId.slice(0, 8)}] turn ${t.turn}: ${t.goal}`).join('\n');
        setMessages((prev) => [
          ...prev,
          { id: Date.now().toString(), sender: 'system', text, timestamp: new Date().toLocaleTimeString() },
        ]);
        return;
      }

      if (cmd === '/resume') {
        if (!arg) {
          setMessages((prev) => [
            ...prev,
            { id: Date.now().toString(), sender: 'system', text: 'Usage: /resume <taskId>', timestamp: new Date().toLocaleTimeString() },
          ]);
          return;
        }
        setStatus('running');
        setStatusText(`Resuming task ${arg}...`);
        await client.resumeTask(arg);
        return;
      }

      if (cmd === '/undo') {
        const { message } = await client.undoEdit();
        setMessages((prev) => [
          ...prev,
          { id: Date.now().toString(), sender: 'system', text: message, timestamp: new Date().toLocaleTimeString() },
        ]);
        return;
      }

      if (cmd === '/exit' || cmd === '/quit') {
        await client.stop();
        exit();
        return;
      }

      if (cmd === '/help') {
        const helpText = [
          'Buzzard TUI Commands:',
          '  /plan [on|off]  - Toggle plan mode (read-only)',
          '  /tasks          - List unfinished durable tasks',
          '  /resume <id>    - Resume a saved task',
          '  /undo           - Revert last file edit',
          '  /clear          - Clear transcript',
          '  /exit           - Quit Buzzard TUI',
          'Shortcuts:',
          '  [Tab] Toggle Plan Mode  •  [PgUp/PgDn] Scroll Transcript  •  [Ctrl+C] Cancel/Quit',
        ].join('\n');
        setMessages((prev) => [
          ...prev,
          { id: Date.now().toString(), sender: 'system', text: helpText, timestamp: new Date().toLocaleTimeString() },
        ]);
        return;
      }
    }

    // Normal task execution
    setMessages((prev) => [
      ...prev,
      { id: Date.now().toString(), sender: 'user', text: trimmed, timestamp: new Date().toLocaleTimeString() },
    ]);

    setTools([]);
    setEvidenceReport(null);
    streamingRef.current = '';
    setStatus('running');
    setStatusText('Thinking...');
    setAutoScroll(true);

    try {
      await client.startRun(trimmed, planMode);
    } catch (err: any) {
      setStatus('error');
      setStatusText(`Task error: ${err.message}`);
      setMessages((prev) => [
        ...prev,
        { id: Date.now().toString(), sender: 'system', text: `Error: ${err.message}`, timestamp: new Date().toLocaleTimeString() },
      ]);
    }
  };

  const handlePageUp = () => {
    setAutoScroll(false);
    setScrollOffset((prev) => Math.max(0, prev - 5));
  };

  const handlePageDown = () => {
    setScrollOffset((prev) => prev + 5);
  };

  // Responsive Layout Calculations
  const isWide = columns >= 110;
  const sidebarWidth = isWide ? 34 : 0;
  const chatWidth = isWide ? columns - sidebarWidth - 1 : columns;

  const headerHeight = 3;
  const bottomHeight = pendingApproval ? 5 : 4;
  const middleHeight = Math.max(6, rows - headerHeight - bottomHeight);

  return (
    <Box flexDirection="column" width={columns} height={rows} overflow="hidden">
      {/* Pinned Top Bar */}
      <Header
        width={columns}
        model={initData?.model || 'loading...'}
        provider={initData?.provider || 'buzzard'}
        workspace={workspace}
        planMode={planMode}
        tokens={tokens}
        cost={cost}
        status={status}
      />

      {/* Middle Viewport (Chat + Docked Sidebar when wide) */}
      <Box flexDirection="row" width={columns} height={middleHeight} overflow="hidden">
        <Transcript
          width={chatWidth}
          height={middleHeight}
          messages={messages}
          tools={tools}
          evidenceReport={evidenceReport}
          scrollOffset={scrollOffset}
          autoScroll={autoScroll}
        />

        {isWide && (
          <Sidebar
            width={sidebarWidth}
            height={middleHeight}
            tasks={tasks}
            tools={tools}
            planMode={planMode}
          />
        )}
      </Box>

      {/* Pinned Bottom Area */}
      {pendingApproval ? (
        <ApprovalDialog
          width={columns}
          request={pendingApproval}
          onRespond={handleApprovalRespond}
        />
      ) : (
        <Composer
          width={columns}
          status={status}
          statusText={statusText}
          planMode={planMode}
          onSubmit={handleCommandSubmit}
          onPageUp={handlePageUp}
          onPageDown={handlePageDown}
        />
      )}
    </Box>
  );
};
