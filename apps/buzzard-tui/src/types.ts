export interface ServerInfo {
  name: string;
  version: string;
}

export interface InitializeResult {
  protocolVersion: string;
  serverInfo: ServerInfo;
  workspace: string;
  model: string;
  provider: string;
  settings: Record<string, any>;
  capabilities: Record<string, any>;
}

export interface ApprovalRequest {
  requestId: string;
  tool: string;
  arguments: Record<string, any>;
  riskClass: string;
  canAllowForSession: boolean;
}

export interface ToolEvent {
  runId: string;
  tool: string;
  arguments?: Record<string, any>;
  durationMs?: number;
  exitCode?: number;
  preview?: string;
  status: 'running' | 'completed' | 'failed';
}

export interface RunMetrics {
  modelCalls?: number;
  turns?: number;
  inputTokens?: number;
  outputTokens?: number;
  estimatedTokens?: boolean;
  elapsedSeconds?: number;
  costUsd?: number | null;
}

export interface RunFinished {
  runId: string;
  status: 'completed' | 'failed' | 'cancelled' | string;
  finalAnswer?: string;
  error?: string;
  metrics?: RunMetrics;
}

export interface TaskItem {
  taskId: string;
  status: string;
  turn: number;
  goal: string;
  updatedAt: string;
}

export interface MessageItem {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  text: string;
  timestamp: string;
  isStreaming?: boolean;
}
