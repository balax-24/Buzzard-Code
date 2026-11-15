import React, { useState, useEffect, useRef } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import TextInput from 'ink-text-input';
import Spinner from 'ink-spinner';
import { RuntimeClient } from './client.js';
import { Header } from './components/Header.js';
import { ChatFeed } from './components/ChatFeed.js';
import { ToolCard } from './components/ToolCard.js';
import { ApprovalDialog } from './components/ApprovalDialog.js';
import { EvidenceView } from './components/EvidenceView.js';
import { StatusBar } from './components/StatusBar.js';
import {
  MessageItem,
  ToolEvent,
  ApprovalRequest,
  InitializeResult,
} from './types.js';

interface AppProps {
  workspace: string;
}

export const App: React.FC<AppProps> = ({ workspace }) => {
  const { exit } = useApp();
  const [initData, setInitData] = useState<InitializeResult | null>(null);
  const [client, setClient] = useState<RuntimeClient | null>(null);
  const [status, setStatus] = useState<'idle' | 'running' | 'approval_required' | 'cancelled' | 'error'>('idle');
  const [statusText, setStatusText] = useState('Connecting to Buzzard Engine...');
  const [planMode, setPlanMode] = useState(false);
  const [tokens, setTokens] = useState(0);
  const [cost, setCost] = useState<number | null>(null);

  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [activeTools, setActiveTools] = useState<ToolEvent[]>([]);
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null);
  const [evidenceReport, setEvidenceReport] = useState<string | null>(null);

  const [inputVal, setInputVal] = useState('');
  const streamingMsgRef = useRef<string>('');

  useEffect(() => {
    const runtime = new RuntimeClient(workspace);

    runtime.setEvents({
      onDelta: (text) => {
        streamingMsgRef.current += text;
        setMessages((prev) => {
          const last = prev[prev.length - 1];
          if (last && last.sender === 'assistant' && last.isStreaming) {
            return [
              ...prev.slice(0, -1),
              { ...last, text: streamingMsgRef.current },
            ];
          }
          return [
            ...prev,
            {
              id: Date.now().toString(),
              sender: 'assistant',
              text: streamingMsgRef.current,
              timestamp: new Date().toLocaleTimeString(),
              isStreaming: true,
            },
          ];
        });
      },

      onToolStart: (tool) => {
        setStatus('running');
        setStatusText(`Executing ${tool.tool}...`);
        setActiveTools((prev) => [...prev, tool]);
      },

      onToolEnd: (tool) => {
        setActiveTools((prev) =>
          prev.map((t) => (t.tool === tool.tool && t.status === 'running' ? tool : t))
        );
      },

      onApprovalRequest: (req) => {
        setStatus('approval_required');
        setStatusText(`Waiting for approval on ${req.tool}`);
        setPendingApproval(req);
      },

      onEvidenceReport: (report) => {
        setEvidenceReport(report);
      },

      onRunFinished: (res) => {
        setStatus(res.status === 'completed' ? 'idle' : res.status === 'cancelled' ? 'cancelled' : 'error');
        setStatusText(res.status === 'completed' ? 'Ready' : `Finished (${res.status})`);
        streamingMsgRef.current = '';

        if (res.metrics) {
          if (res.metrics.inputTokens || res.metrics.outputTokens) {
            setTokens((prev) => prev + (res.metrics?.inputTokens || 0) + (res.metrics?.outputTokens || 0));
          }
          if (res.metrics.costUsd) {
            setCost((prev) => (prev || 0) + (res.metrics?.costUsd || 0));
          }
        }

        // Finalize streaming flag
        setMessages((prev) =>
          prev.map((m) => (m.isStreaming ? { ...m, isStreaming: false } : m))
        );
      },

      onError: (err) => {
        setStatus('error');
        setStatusText(`Error: ${err.message}`);
      },

      onExit: () => {
        setStatusText('Engine process disconnected');
      },
    });

    runtime
      .start()
      .then((info) => {
        setInitData(info);
        setClient(runtime);
        setStatus('idle');
        setStatusText('Engine ready');
        setMessages([
          {
            id: 'init',
            sender: 'system',
            text: `Connected to ${info.serverInfo.name} ${info.serverInfo.version} (${info.provider}/${info.model})`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      })
      .catch((err) => {
        setStatus('error');
        setStatusText(`Failed to connect engine: ${err.message}`);
      });

    return () => {
      runtime.stop().catch(() => {});
    };
  }, [workspace]);

  useInput((input, key) => {
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
    setStatusText(`Approval responded: ${decision}`);
    await client.respondApproval(reqId, decision).catch(() => {});
  };

  const handleCommandSubmit = async (val: string) => {
    const trimmed = val.trim();
    setInputVal('');
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
        setActiveTools([]);
        setEvidenceReport(null);
        return;
      }

      if (cmd === '/tasks') {
        const { tasks } = await client.listTasks();
        const text = tasks.length === 0
          ? 'No unfinished tasks in this workspace.'
          : 'Saved unfinished tasks:\n' + tasks.map((t) => `  • [${t.taskId.slice(0, 8)}] turn ${t.turn}: ${t.goal}`).join('\n');
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
          '  /plan [on|off]  - Toggle plan mode',
          '  /tasks          - List unfinished durable tasks',
          '  /resume <id>    - Resume saved task',
          '  /undo           - Revert last file edit',
          '  /clear          - Clear screen',
          '  /exit           - Exit TUI',
          'Shortcuts:',
          '  [Tab] Toggle Plan Mode  •  [Ctrl+C] Cancel Task / Exit',
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

    setActiveTools([]);
    setEvidenceReport(null);
    streamingMsgRef.current = '';
    setStatus('running');
    setStatusText('Thinking...');

    try {
      await client.startRun(trimmed, planMode);
    } catch (err: any) {
      setStatus('error');
      setStatusText(`Run failed: ${err.message}`);
      setMessages((prev) => [
        ...prev,
        { id: Date.now().toString(), sender: 'system', text: `Error: ${err.message}`, timestamp: new Date().toLocaleTimeString() },
      ]);
    }
  };

  return (
    <Box flexDirection="column" padding={1}>
      <Header
        model={initData?.model || 'loading...'}
        provider={initData?.provider || 'buzzard'}
        workspace={workspace}
        planMode={planMode}
        tokens={tokens}
        cost={cost}
        status={status}
      />

      <ChatFeed
        messages={messages}
        tools={activeTools}
        evidenceReport={evidenceReport || undefined}
      />

      {pendingApproval && (
        <ApprovalDialog
          request={pendingApproval}
          onRespond={handleApprovalRespond}
        />
      )}

      {status === 'running' && !pendingApproval && (
        <Box marginY={0}>
          <Text color="cyan"><Spinner type="dots" /> </Text>
          <Text dimColor> {statusText}</Text>
        </Box>
      )}

      {!pendingApproval && (
        <Box marginTop={1} flexDirection="row">
          <Text color="green" bold>❯ </Text>
          <TextInput
            value={inputVal}
            onChange={setInputVal}
            onSubmit={handleCommandSubmit}
            placeholder={status === 'running' ? 'Task running... (type /help or prompt)' : 'Ask Buzzard anything... (/help for commands)'}
          />
        </Box>
      )}

      <StatusBar planMode={planMode} status={statusText} />
    </Box>
  );
};
