'use client';

import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { Stats, Session, Log, AttackPattern } from '@/lib/types';
import StatsCards from '@/components/StatsCards';
import LiveAttackFeed from '@/components/LiveAttackFeed';
import SessionsTable from '@/components/SessionsTable';
import AttackPatterns from '@/components/AttackPatterns';
import ChatBot from '@/components/ChatBot';
import { Shield, RefreshCw } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [logs, setLogs] = useState<Log[]>([]);
  const [attackPatterns, setAttackPatterns] = useState<AttackPattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  const fetchData = async () => {
    try {
      setError(null);
      const [statsData, sessionsData, logsData, patternsData] = await Promise.all([
        api.getStats(),
        api.getSessions(true),
        api.getLogs(undefined, 50),
        api.getPatterns(),
      ]);

      setStats(statsData);
      setSessions(sessionsData.sessions);
      setLogs(logsData.logs);
      setAttackPatterns(patternsData.attack_types);
      setLastUpdate(new Date());

      // Log to console for debugging
      console.log('✅ Data fetched successfully:', {
        totalInteractions: statsData.total_interactions,
        activeSessions: statsData.active_sessions,
        logsCount: logsData.logs.length,
        attackTypes: patternsData.attack_types.length
      });
    } catch (error) {
      console.error('Error fetching data:', error);
      setError(error instanceof Error ? error.message : `Cannot connect to backend API at ${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Auto-refresh every 5 seconds
    const interval = setInterval(fetchData, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">QuantumShield</h1>
                <p className="text-sm text-gray-400">AI-Powered Honeypot Dashboard</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={fetchData}
                className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg transition-colors group"
                disabled={loading}
              >
                <RefreshCw className={`w-4 h-4 text-cyan-400 ${loading ? 'animate-spin' : 'group-hover:rotate-180 transition-transform duration-500'}`} />
                <span className="text-sm text-gray-300">Refresh</span>
              </button>

              <a
                href="/reports"
                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-lg transition-colors"
              >
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <span className="text-sm text-white font-medium">View Report</span>
              </a>
            </div>
          </div>

          <div className="mt-2 text-xs text-gray-500">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="space-y-6">
          {/* Error Banner */}
          {error && (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <div className="text-red-400 text-2xl">⚠️</div>
                <div className="flex-1">
                  <h3 className="text-red-400 font-semibold mb-1">Backend Connection Error</h3>
                  <p className="text-red-300 text-sm">{error}</p>
                  <p className="text-red-400 text-xs mt-2">Make sure the backend is running: <code className="bg-red-900/30 px-2 py-1 rounded">cd honeypot && python main.py</code></p>
                </div>
              </div>
            </div>
          )}
          {/* Stats Cards */}
          <StatsCards stats={stats} />

          {/* Two Column Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Live Attack Feed */}
            <LiveAttackFeed logs={logs} />

            {/* Attack Patterns */}
            <AttackPatterns attackTypes={attackPatterns} />
          </div>

          {/* Sessions Table */}
          <SessionsTable sessions={sessions} />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-900/50 backdrop-blur-sm mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-sm text-gray-500">
            <p>QuantumShield Honeypot v1.0 - Monitoring and analyzing attacker behavior</p>
          </div>
        </div>
      </footer>

      {/* AI ChatBot */}
      <ChatBot />
    </div>
  );
}

