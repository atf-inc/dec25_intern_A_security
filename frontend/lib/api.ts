import { Stats, Session, Log, AttackPattern, TimelineData, ChatQueryResponse, ForensicsData, ChatSuggestions } from './types';

// Get API base URL - baked in at build time for Cloud Run
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Helper to build URL with query params (avoids new URL() which can throw on client)
function buildUrl(path: string, params?: Record<string, string>): string {
    let url = `${API_BASE}${path}`;
    if (params && Object.keys(params).length > 0) {
        const queryString = Object.entries(params)
            .filter(([_, v]) => v !== undefined && v !== null)
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');
        if (queryString) {
            url += `?${queryString}`;
        }
    }
    return url;
}

export const api = {
    async getStats(): Promise<Stats> {
        const res = await fetch(`${API_BASE}/api/analytics/stats`);
        if (!res.ok) throw new Error('Failed to fetch stats');
        return res.json();
    },

    async getSessions(activeOnly: boolean = false): Promise<{ count: number; sessions: Session[] }> {
        const params: Record<string, string> = {};
        if (activeOnly) params.active_only = 'true';
        
        const res = await fetch(buildUrl('/api/analytics/sessions', params));
        if (!res.ok) throw new Error('Failed to fetch sessions');
        return res.json();
    },

    async getLogs(sessionId?: string, limit: number = 100): Promise<{ count: number; total: number; logs: Log[] }> {
        const params: Record<string, string> = { limit: limit.toString() };
        if (sessionId) params.session_id = sessionId;
        
        const res = await fetch(buildUrl('/api/analytics/logs', params));
        if (!res.ok) throw new Error('Failed to fetch logs');
        return res.json();
    },

    async getPatterns(): Promise<{ attack_types: AttackPattern[]; top_ips: AttackPattern[] }> {
        const res = await fetch(`${API_BASE}/api/analytics/patterns`);
        if (!res.ok) throw new Error('Failed to fetch patterns');
        return res.json();
    },

    async getTimeline(hours: number = 24): Promise<{ hours: number; data: TimelineData[] }> {
        const res = await fetch(buildUrl('/api/analytics/timeline', { hours: hours.toString() }));
        if (!res.ok) throw new Error('Failed to fetch timeline');
        return res.json();
    },

    async getThreatSummary(sessionId: string): Promise<any> {
        const res = await fetch(`${API_BASE}/api/analytics/summary/${sessionId}`);
        if (!res.ok) throw new Error('Failed to fetch threat summary');
        return res.json();
    },

    async getAttackPlayback(sessionId: string): Promise<any> {
        const res = await fetch(`${API_BASE}/api/analytics/playback/${sessionId}`);
        if (!res.ok) throw new Error('Failed to fetch attack playback');
        return res.json();
    },

    async downloadWeeklyReport(): Promise<Blob> {
        const res = await fetch(`${API_BASE}/api/analytics/report/weekly`);
        if (!res.ok) throw new Error('Failed to download report');
        return res.blob();
    },

    // Chat API methods
    async sendChatQuery(message: string): Promise<ChatQueryResponse> {
        const res = await fetch(`${API_BASE}/api/chat/query`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ message }),
        });
        if (!res.ok) throw new Error('Failed to send chat query');
        return res.json();
    },

    async getForensicsAnalysis(sessionId: string): Promise<ForensicsData> {
        const res = await fetch(`${API_BASE}/api/chat/forensics/${sessionId}`, {
            method: 'POST',
        });
        if (!res.ok) throw new Error('Failed to get forensics analysis');
        return res.json();
    },

    async getChatSuggestions(): Promise<ChatSuggestions> {
        const res = await fetch(`${API_BASE}/api/chat/suggestions`);
        if (!res.ok) throw new Error('Failed to fetch suggestions');
        return res.json();
    },
};
