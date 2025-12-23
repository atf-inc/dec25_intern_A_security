import { Stats, Session, Log, AttackPattern, TimelineData, ChatQueryResponse, ForensicsData, ChatSuggestions } from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const api = {
    async getStats(): Promise<Stats> {
        const res = await fetch(`${API_BASE}/api/analytics/stats`);
        if (!res.ok) throw new Error('Failed to fetch stats');
        return res.json();
    },

    async getSessions(activeOnly: boolean = false): Promise<{ count: number; sessions: Session[] }> {
        const url = new URL(`${API_BASE}/api/analytics/sessions`);
        if (activeOnly) url.searchParams.set('active_only', 'true');

        const res = await fetch(url.toString());
        if (!res.ok) throw new Error('Failed to fetch sessions');
        return res.json();
    },

    async getLogs(sessionId?: string, limit: number = 100): Promise<{ count: number; total: number; logs: Log[] }> {
        const url = new URL(`${API_BASE}/api/analytics/logs`);
        if (sessionId) url.searchParams.set('session_id', sessionId);
        url.searchParams.set('limit', limit.toString());

        const res = await fetch(url.toString());
        if (!res.ok) throw new Error('Failed to fetch logs');
        return res.json();
    },

    async getPatterns(): Promise<{ attack_types: AttackPattern[]; top_ips: AttackPattern[] }> {
        const res = await fetch(`${API_BASE}/api/analytics/patterns`);
        if (!res.ok) throw new Error('Failed to fetch patterns');
        return res.json();
    },

    async getTimeline(hours: number = 24): Promise<{ hours: number; data: TimelineData[] }> {
        const url = new URL(`${API_BASE}/api/analytics/timeline`);
        url.searchParams.set('hours', hours.toString());

        const res = await fetch(url.toString());
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

    // New methods for two-column attack display
    async getGroupedAttacks(): Promise<{ blocked: Log[]; trapped: Log[] }> {
        const res = await fetch(`${API_BASE}/api/analytics/grouped-attacks`);
        if (!res.ok) throw new Error('Failed to fetch grouped attacks');
        return res.json();
    },

    async getSessionDetails(sessionId: string): Promise<{ session_id: string; session_info: any; total_requests: number; logs: Log[] }> {
        const res = await fetch(`${API_BASE}/api/analytics/session-details/${sessionId}`);
        if (!res.ok) throw new Error('Failed to fetch session details');
        return res.json();
    },
};
