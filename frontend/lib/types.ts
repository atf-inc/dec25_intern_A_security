export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Session {
  _id: string;
  session_id: string;
  ip_address: string;
  user_agent: string;
  start_time: string;
  active: boolean;
  // New duration fields
  end_time?: string;
  duration_seconds?: number;
  context: {
    current_directory: string;
    user: string;
    history: Array<{
      cmd: string;
      res: string;
    }>;
  };
}

export interface Log {
  _id: string;
  timestamp: string;
  session_id: string;
  ip: string;
  type: string;
  payload: string;
  response: string;
  // New analytics fields
  attack_type?: string;
  severity?: SeverityLevel;
  ml_verdict?: string;
  ml_confidence?: number;
  http_method?: string;
  path?: string;
  query_params?: Record<string, string>;
  headers?: {
    user_agent?: string;
    referer?: string;
    content_type?: string;
    origin?: string;
    x_forwarded_for?: string;
  };
  body_size?: number;
  response_time_ms?: number;
}

export interface Stats {
  total_interactions: number;
  active_sessions: number;
  total_sessions: number;
  recent_activity_24h: number;
  cache: {
    size: number;
    max_size: number;
    hits: number;
    misses: number;
    hit_rate: string;
    ttl_seconds: number;
  };
  llm: {
    total_requests: number;
    errors: number;
    model: string;
  };
  uptime: string;
}

export interface AttackPattern {
  _id: string;
  count: number;
}

export interface TimelineData {
  _id: string;
  count: number;
}

// Chat types
export type ChatRenderType = 'text' | 'table' | 'bar_chart' | 'pie_chart' | 'line_chart' | 'forensics';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  render_type?: ChatRenderType;
  data?: ChartDataPoint[] | TableRow[] | ForensicsData;
  timestamp: Date;
}

export interface ChartDataPoint {
  name: string;
  value: number;
  [key: string]: string | number;
}

export interface TableRow {
  [key: string]: string | number | boolean;
}

export interface ForensicsData {
  session_id: string;
  ip_address?: string;
  command_history: Array<{ cmd: string; res: string }>;
  analysis: string;
  intent: string;
  threat_level: string;
  blocked_actions: string[];
}

export interface ChatQueryResponse {
  content: string;
  render_type: ChatRenderType;
  data?: ChartDataPoint[] | TableRow[];
  query_executed?: string;
}

export interface ChatSuggestions {
  suggestions: string[];
}