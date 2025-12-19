'use client';

import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { FileText, Calendar, TrendingUp, Shield, Download } from 'lucide-react';

export default function ReportsPage() {
    const [stats, setStats] = useState<any>(null);
    const [patterns, setPatterns] = useState<any>(null);
    const [timeline, setTimeline] = useState<any>(null);
    const [sessions, setSessions] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [dateRange, setDateRange] = useState(7); // days

    useEffect(() => {
        fetchReportData();
    }, [dateRange]);

    const fetchReportData = async () => {
        setLoading(true);
        try {
            const [statsData, patternsData, timelineData, sessionsData] = await Promise.all([
                api.getStats(),
                api.getPatterns(),
                api.getTimeline(dateRange * 24),
                api.getSessions(false)
            ]);

            setStats(statsData);
            setPatterns(patternsData);
            setTimeline(timelineData);
            setSessions(sessionsData.sessions);
        } catch (error) {
            console.error('Error fetching report data:', error);
        } finally {
            setLoading(false);
        }
    };

    const exportToHTML = () => {
        const reportHTML = document.getElementById('report-content')?.innerHTML;
        const fullHTML = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>QuantumShield Report - ${new Date().toLocaleDateString()}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
                    h1 { color: #1a1a1a; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
                    h2 { color: #374151; margin-top: 30px; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
                    th { background: #f3f4f6; font-weight: 600; }
                    .stat-card { display: inline-block; margin: 10px; padding: 20px; background: #f9fafb; border-radius: 8px; min-width: 200px; }
                    .stat-value { font-size: 32px; font-weight: bold; color: #3b82f6; }
                    .stat-label { color: #6b7280; margin-top: 5px; }
                </style>
            </head>
            <body>
                <div class="container">
                    ${reportHTML}
                </div>
            </body>
            </html>
        `;

        const blob = new Blob([fullHTML], { type: 'text/html' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `quantum_shield_report_${new Date().toISOString().split('T')[0]}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black flex items-center justify-center">
                <div className="text-white text-xl">Loading report data...</div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black">
            {/* Header */}
            <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-gradient-to-br from-purple-500 to-blue-600 rounded-lg">
                                <FileText className="w-6 h-6 text-white" />
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold text-white">Threat Intelligence Report</h1>
                                <p className="text-sm text-gray-400">Last {dateRange} days analysis</p>
                            </div>
                        </div>

                        <div className="flex items-center gap-3">
                            <select
                                value={dateRange}
                                onChange={(e) => setDateRange(Number(e.target.value))}
                                className="px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-300 focus:outline-none focus:border-cyan-500"
                            >
                                <option value={1}>Last 24 hours</option>
                                <option value={7}>Last 7 days</option>
                                <option value={30}>Last 30 days</option>
                            </select>

                            <button
                                onClick={exportToHTML}
                                className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-lg transition-colors"
                            >
                                <Download className="w-4 h-4 text-white" />
                                <span className="text-sm text-white font-medium">Export HTML</span>
                            </button>

                            <a
                                href="/"
                                className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg transition-colors"
                            >
                                <Shield className="w-4 h-4 text-cyan-400" />
                                <span className="text-sm text-gray-300">Back to Dashboard</span>
                            </a>
                        </div>
                    </div>
                </div>
            </header>

            {/* Report Content */}
            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <div id="report-content" className="space-y-8">
                    {/* Executive Summary */}
                    <section className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
                        <h2 className="text-xl font-semibold text-white mb-6 flex items-center gap-2">
                            <TrendingUp className="w-5 h-5 text-cyan-400" />
                            Executive Summary
                        </h2>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div className="bg-gray-900/50 p-6 rounded-lg border border-gray-700">
                                <div className="text-3xl font-bold text-cyan-400">{stats?.total_interactions || 0}</div>
                                <div className="text-sm text-gray-400 mt-2">Total Attacks</div>
                            </div>
                            <div className="bg-gray-900/50 p-6 rounded-lg border border-gray-700">
                                <div className="text-3xl font-bold text-purple-400">{stats?.total_sessions || 0}</div>
                                <div className="text-sm text-gray-400 mt-2">Unique Sessions</div>
                            </div>
                            <div className="bg-gray-900/50 p-6 rounded-lg border border-gray-700">
                                <div className="text-3xl font-bold text-emerald-400">{stats?.active_sessions || 0}</div>
                                <div className="text-sm text-gray-400 mt-2">Active Sessions</div>
                            </div>
                            <div className="bg-gray-900/50 p-6 rounded-lg border border-gray-700">
                                <div className="text-3xl font-bold text-orange-400">{stats?.recent_activity_24h || 0}</div>
                                <div className="text-sm text-gray-400 mt-2">Last 24h Activity</div>
                            </div>
                        </div>

                        <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                            <p className="text-sm text-blue-300">
                                <strong>Report Period:</strong> {new Date(Date.now() - dateRange * 24 * 60 * 60 * 1000).toLocaleDateString()} - {new Date().toLocaleDateString()}
                            </p>
                            <p className="text-sm text-blue-300 mt-1">
                                <strong>Generated:</strong> {new Date().toLocaleString()}
                            </p>
                        </div>
                    </section>

                    {/* Attack Types Distribution */}
                    <section className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
                        <h2 className="text-xl font-semibold text-white mb-6">Attack Types Distribution</h2>

                        {patterns?.attack_types && patterns.attack_types.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead className="bg-gray-900/50">
                                        <tr>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Attack Type</th>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Count</th>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Percentage</th>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Visual</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-700">
                                        {patterns.attack_types.map((attack: any, index: number) => {
                                            const total = patterns.attack_types.reduce((sum: number, a: any) => sum + a.count, 0);
                                            const percentage = ((attack.count / total) * 100).toFixed(1);
                                            return (
                                                <tr key={index} className="hover:bg-gray-700/30">
                                                    <td className="px-4 py-3 text-sm text-gray-300 font-medium">{attack._id || 'Unknown'}</td>
                                                    <td className="px-4 py-3 text-sm text-cyan-400">{attack.count}</td>
                                                    <td className="px-4 py-3 text-sm text-gray-400">{percentage}%</td>
                                                    <td className="px-4 py-3">
                                                        <div className="w-full bg-gray-700 rounded-full h-2">
                                                            <div
                                                                className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full"
                                                                style={{ width: `${percentage}%` }}
                                                            ></div>
                                                        </div>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <p className="text-gray-400 text-center py-8">No attack data available for this period</p>
                        )}
                    </section>

                    {/* Top Attacker IPs */}
                    <section className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
                        <h2 className="text-xl font-semibold text-white mb-6">Top Attacker IP Addresses</h2>

                        {patterns?.top_ips && patterns.top_ips.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead className="bg-gray-900/50">
                                        <tr>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Rank</th>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">IP Address</th>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Attack Count</th>
                                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Threat Level</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-700">
                                        {patterns.top_ips.map((ip: any, index: number) => (
                                            <tr key={index} className="hover:bg-gray-700/30">
                                                <td className="px-4 py-3 text-sm text-gray-400">#{index + 1}</td>
                                                <td className="px-4 py-3 text-sm text-cyan-400 font-mono">{ip._id}</td>
                                                <td className="px-4 py-3 text-sm text-gray-300">{ip.count}</td>
                                                <td className="px-4 py-3">
                                                    <span className={`px-2 py-1 rounded text-xs font-semibold ${ip.count > 50 ? 'bg-red-500/20 text-red-400' :
                                                            ip.count > 20 ? 'bg-orange-500/20 text-orange-400' :
                                                                'bg-yellow-500/20 text-yellow-400'
                                                        }`}>
                                                        {ip.count > 50 ? 'High' : ip.count > 20 ? 'Medium' : 'Low'}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <p className="text-gray-400 text-center py-8">No attacker IP data available</p>
                        )}
                    </section>

                    {/* Recent Sessions */}
                    <section className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
                        <h2 className="text-xl font-semibold text-white mb-6">Recent Attack Sessions</h2>

                        {sessions && sessions.length > 0 ? (
                            <div className="space-y-3">
                                {sessions.slice(0, 10).map((session: any) => (
                                    <div key={session._id} className="bg-gray-900/50 p-4 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
                                        <div className="flex items-center justify-between">
                                            <div className="flex-1">
                                                <div className="flex items-center gap-3">
                                                    <span className="text-sm font-mono text-cyan-400">{session.ip_address}</span>
                                                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${session.active ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-500/20 text-gray-400'
                                                        }`}>
                                                        {session.active ? 'Active' : 'Inactive'}
                                                    </span>
                                                </div>
                                                <p className="text-xs text-gray-400 mt-1">{session.user_agent}</p>
                                            </div>
                                            <div className="text-right">
                                                <div className="text-sm text-gray-300">{session.context.history?.length || 0} interactions</div>
                                                <div className="text-xs text-gray-500">{new Date(session.start_time).toLocaleString()}</div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <p className="text-gray-400 text-center py-8">No session data available</p>
                        )}
                    </section>
                </div>
            </main>
        </div>
    );
}
