'use client';

import { Session } from '@/lib/types';
import { formatDistanceToNow } from 'date-fns';
import { Users, Circle, Brain, Play, ChevronDown, ChevronUp, X, Clock } from 'lucide-react';
import { useState } from 'react';
import { api } from '@/lib/api';

interface SessionsTableProps {
    sessions: Session[];
}

// Helper to format duration in human-readable format
function formatDuration(seconds?: number): string {
    if (seconds === undefined || seconds === null) return '-';
    
    if (seconds < 60) {
        return `${Math.round(seconds)}s`;
    } else if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.round(seconds % 60);
        return `${mins}m ${secs}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }
}

export default function SessionsTable({ sessions }: SessionsTableProps) {
    const [expandedSession, setExpandedSession] = useState<string | null>(null);
    const [showSummaryModal, setShowSummaryModal] = useState(false);
    const [showPlaybackModal, setShowPlaybackModal] = useState(false);
    const [summaryData, setSummaryData] = useState<any>(null);
    const [playbackData, setPlaybackData] = useState<any>(null);
    const [loading, setLoading] = useState(false);

    const handleViewSummary = async (sessionId: string) => {
        setLoading(true);
        try {
            const data = await api.getThreatSummary(sessionId);
            setSummaryData(data);
            setShowSummaryModal(true);
        } catch (error) {
            console.error('Error fetching summary:', error);
            alert('Failed to load AI summary. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    const handleViewPlayback = async (sessionId: string) => {
        setLoading(true);
        try {
            const data = await api.getAttackPlayback(sessionId);
            setPlaybackData(data);
            setShowPlaybackModal(true);
        } catch (error) {
            console.error('Error fetching playback:', error);
            alert('Failed to load attack playback. Make sure the backend is running.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <>
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg overflow-hidden">
                <div className="flex items-center gap-2 p-4 border-b border-gray-700">
                    <Users className="w-5 h-5 text-cyan-400" />
                    <h2 className="text-lg font-semibold text-white">Active Sessions</h2>
                    <span className="ml-auto text-sm text-gray-400">{sessions.length} total</span>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead className="bg-gray-900/50">
                            <tr>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">IP Address</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">User Agent</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Started</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Duration</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Interactions</th>
                                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-700">
                            {sessions.length === 0 ? (
                                <tr>
                                    <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                                        No active sessions
                                    </td>
                                </tr>
                            ) : (
                                sessions.map((session) => (
                                    <tr key={session._id} className="hover:bg-gray-700/30 transition-colors">
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-2">
                                                <Circle
                                                    className={`w-2 h-2 ${session.active ? 'fill-emerald-400 text-emerald-400' : 'fill-gray-400 text-gray-400'
                                                        }`}
                                                />
                                                <span className={`text-xs font-medium ${session.active ? 'text-emerald-400' : 'text-gray-400'}`}>
                                                    {session.active ? 'Active' : 'Inactive'}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-sm font-mono text-cyan-400">{session.ip_address}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-sm text-gray-300 max-w-xs truncate block">
                                                {session.user_agent}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-sm text-gray-400">
                                                {(() => {
                                                    try {
                                                        return formatDistanceToNow(new Date(session.start_time), { addSuffix: true });
                                                    } catch {
                                                        return 'Unknown';
                                                    }
                                                })()}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-1 text-sm text-gray-300">
                                                <Clock className="w-3 h-3 text-gray-500" />
                                                <span>{formatDuration(session.duration_seconds)}</span>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className="text-sm text-gray-300">{session.context.history?.length || 0}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={() => handleViewSummary(session.session_id)}
                                                    disabled={loading}
                                                    className="p-1.5 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/50 rounded text-purple-400 hover:text-purple-300 transition-colors disabled:opacity-50"
                                                    title="AI Summary"
                                                >
                                                    <Brain className="w-4 h-4" />
                                                </button>
                                                <button
                                                    onClick={() => handleViewPlayback(session.session_id)}
                                                    disabled={loading}
                                                    className="p-1.5 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/50 rounded text-cyan-400 hover:text-cyan-300 transition-colors disabled:opacity-50"
                                                    title="Attack Playback"
                                                >
                                                    <Play className="w-4 h-4" />
                                                </button>
                                                <button
                                                    onClick={() => setExpandedSession(expandedSession === session._id ? null : session._id)}
                                                    className="p-1.5 bg-gray-600/20 hover:bg-gray-600/30 border border-gray-600/50 rounded text-gray-400 hover:text-gray-300 transition-colors"
                                                    title="Toggle Details"
                                                >
                                                    {expandedSession === session._id ? (
                                                        <ChevronUp className="w-4 h-4" />
                                                    ) : (
                                                        <ChevronDown className="w-4 h-4" />
                                                    )}
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* AI Summary Modal */}
            {showSummaryModal && summaryData && (
                <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-5xl w-full max-h-[90vh] overflow-hidden flex flex-col">
                        <div className="flex items-center justify-between p-4 border-b border-gray-700">
                            <div className="flex items-center gap-2">
                                <Brain className="w-5 h-5 text-purple-400" />
                                <h3 className="text-lg font-semibold text-white">AI Threat Analysis</h3>
                                {summaryData.analysis && (
                                    <span className={`ml-2 px-2 py-1 rounded text-xs font-semibold ${summaryData.analysis.threat_level === 'Critical' ? 'bg-red-500/20 text-red-400' :
                                            summaryData.analysis.threat_level === 'High' ? 'bg-orange-500/20 text-orange-400' :
                                                summaryData.analysis.threat_level === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                    'bg-green-500/20 text-green-400'
                                        }`}>
                                        {summaryData.analysis.threat_level} Risk
                                    </span>
                                )}
                            </div>
                            <button
                                onClick={() => setShowSummaryModal(false)}
                                className="p-1 hover:bg-gray-700 rounded transition-colors"
                            >
                                <X className="w-5 h-5 text-gray-400" />
                            </button>
                        </div>
                        <div className="p-6 overflow-y-auto">
                            {summaryData.error ? (
                                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
                                    <p className="text-red-400">{summaryData.error}</p>
                                    {summaryData.fallback_summary && (
                                        <p className="text-gray-300 mt-2">{summaryData.fallback_summary}</p>
                                    )}
                                </div>
                            ) : summaryData.analysis ? (
                                <div className="space-y-6">
                                    {/* Header Stats */}
                                    <div className="grid grid-cols-3 gap-4">
                                        <div className="bg-gray-900/50 p-4 rounded-lg border border-gray-700">
                                            <div className="text-2xl font-bold text-purple-400">{summaryData.analysis.risk_score}/100</div>
                                            <div className="text-sm text-gray-400 mt-1">Risk Score</div>
                                        </div>
                                        <div className="bg-gray-900/50 p-4 rounded-lg border border-gray-700">
                                            <div className="text-2xl font-bold text-cyan-400">{summaryData.total_attacks}</div>
                                            <div className="text-sm text-gray-400 mt-1">Total Attacks</div>
                                        </div>
                                        <div className="bg-gray-900/50 p-4 rounded-lg border border-gray-700">
                                            <div className="text-sm font-mono text-cyan-400">{summaryData.ip_address}</div>
                                            <div className="text-sm text-gray-400 mt-1">Attacker IP</div>
                                        </div>
                                    </div>

                                    {/* Executive Summary */}
                                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                                        <h4 className="text-sm font-semibold text-blue-400 mb-2">Executive Summary</h4>
                                        <p className="text-gray-300">{summaryData.analysis.executive_summary}</p>
                                    </div>

                                    {/* Attacker Profile */}
                                    <div>
                                        <h4 className="text-sm font-semibold text-white mb-2">Attacker Profile</h4>
                                        <p className="text-gray-300">{summaryData.analysis.attacker_profile}</p>
                                    </div>

                                    {/* Attack Techniques */}
                                    <div>
                                        <h4 className="text-sm font-semibold text-white mb-3">Attack Techniques</h4>
                                        <div className="space-y-2">
                                            {summaryData.analysis.attack_techniques.map((technique: any, index: number) => (
                                                <div key={index} className="bg-gray-900/50 p-3 rounded-lg border border-gray-700">
                                                    <div className="flex items-center justify-between mb-1">
                                                        <span className="text-sm font-medium text-cyan-400">{technique.name}</span>
                                                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${technique.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                                                                technique.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                                                                    technique.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                                        'bg-green-500/20 text-green-400'
                                                            }`}>
                                                            {technique.severity}
                                                        </span>
                                                    </div>
                                                    <p className="text-xs text-gray-400">{technique.description}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Timeline */}
                                    {summaryData.analysis.timeline && summaryData.analysis.timeline.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-semibold text-white mb-3">Attack Timeline</h4>
                                            <div className="space-y-3">
                                                {summaryData.analysis.timeline.map((phase: any, index: number) => (
                                                    <div key={index} className="relative pl-6 pb-4 border-l-2 border-purple-500/30 last:pb-0">
                                                        <div className="absolute left-[-5px] top-0 w-2 h-2 bg-purple-500 rounded-full"></div>
                                                        <div className="bg-gray-900/50 p-3 rounded-lg border border-gray-700">
                                                            <div className="flex items-center justify-between mb-2">
                                                                <span className="text-sm font-medium text-purple-400">{phase.phase}</span>
                                                                <span className="text-xs text-gray-500">{new Date(phase.timestamp).toLocaleString()}</span>
                                                            </div>
                                                            <ul className="space-y-1">
                                                                {phase.actions.map((action: string, i: number) => (
                                                                    <li key={i} className="text-xs text-gray-300 flex items-start gap-2">
                                                                        <span className="text-cyan-400 mt-0.5">•</span>
                                                                        <span>{action}</span>
                                                                    </li>
                                                                ))}
                                                            </ul>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Indicators of Compromise */}
                                    {summaryData.analysis.indicators_of_compromise && summaryData.analysis.indicators_of_compromise.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-semibold text-white mb-2">Indicators of Compromise (IOCs)</h4>
                                            <div className="bg-gray-900/50 p-3 rounded-lg border border-gray-700">
                                                <ul className="space-y-1">
                                                    {summaryData.analysis.indicators_of_compromise.map((ioc: string, index: number) => (
                                                        <li key={index} className="text-xs text-gray-300 font-mono flex items-start gap-2">
                                                            <span className="text-red-400 mt-0.5">⚠</span>
                                                            <span>{ioc}</span>
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        </div>
                                    )}

                                    {/* MITRE ATT&CK Tactics */}
                                    {summaryData.analysis.mitre_tactics && summaryData.analysis.mitre_tactics.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-semibold text-white mb-2">MITRE ATT&CK Tactics</h4>
                                            <div className="flex flex-wrap gap-2">
                                                {summaryData.analysis.mitre_tactics.map((tactic: string, index: number) => (
                                                    <span key={index} className="px-3 py-1 bg-orange-500/20 border border-orange-500/30 rounded text-xs text-orange-400 font-medium">
                                                        {tactic}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Recommended Actions */}
                                    <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4">
                                        <h4 className="text-sm font-semibold text-emerald-400 mb-3">Recommended Actions</h4>
                                        <ul className="space-y-2">
                                            {summaryData.analysis.recommended_actions.map((action: string, index: number) => (
                                                <li key={index} className="text-sm text-gray-300 flex items-start gap-2">
                                                    <span className="text-emerald-400 mt-0.5">✓</span>
                                                    <span>{action}</span>
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                </div>
                            ) : (
                                <pre className="text-sm text-gray-300 whitespace-pre-wrap">
                                    {JSON.stringify(summaryData, null, 2)}
                                </pre>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Attack Playback Modal */}
            {showPlaybackModal && playbackData && (
                <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
                    <div className="bg-gray-800 border border-gray-700 rounded-lg max-w-4xl w-full max-h-[80vh] overflow-hidden flex flex-col">
                        <div className="flex items-center justify-between p-4 border-b border-gray-700">
                            <div className="flex items-center gap-2">
                                <Play className="w-5 h-5 text-cyan-400" />
                                <h3 className="text-lg font-semibold text-white">Attack Playback</h3>
                                <span className="text-sm text-gray-400">({playbackData.total_steps} steps)</span>
                            </div>
                            <button
                                onClick={() => setShowPlaybackModal(false)}
                                className="p-1 hover:bg-gray-700 rounded transition-colors"
                            >
                                <X className="w-5 h-5 text-gray-400" />
                            </button>
                        </div>
                        <div className="p-6 overflow-y-auto">
                            <div className="space-y-4">
                                <div className="bg-gray-900/50 p-4 rounded-lg border border-gray-700">
                                    <div className="grid grid-cols-2 gap-4 text-sm">
                                        <div>
                                            <span className="text-gray-400">IP Address:</span>
                                            <span className="ml-2 text-cyan-400 font-mono">{playbackData.ip_address}</span>
                                        </div>
                                        <div>
                                            <span className="text-gray-400">Started:</span>
                                            <span className="ml-2 text-gray-300">{new Date(playbackData.start_time).toLocaleString()}</span>
                                        </div>
                                    </div>
                                    <div className="mt-2">
                                        <span className="text-gray-400 text-sm">User Agent:</span>
                                        <p className="text-gray-300 text-sm mt-1">{playbackData.user_agent}</p>
                                    </div>
                                </div>

                                {playbackData.steps.map((step: any, index: number) => (
                                    <div key={index} className="bg-gray-900/30 p-4 rounded-lg border border-gray-700">
                                        <div className="flex items-center gap-2 mb-2">
                                            <span className="bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded text-xs font-semibold">
                                                Step {step.step}
                                            </span>
                                            <span className="text-xs text-gray-400">{new Date(step.timestamp).toLocaleTimeString()}</span>
                                            <span className="ml-auto text-xs text-purple-400">{step.attack_type}</span>
                                        </div>
                                        <div className="space-y-2">
                                            <div>
                                                <span className="text-xs text-gray-500">Payload:</span>
                                                <pre className="text-xs text-gray-300 bg-black/30 p-2 rounded mt-1 overflow-x-auto">
                                                    {step.payload}
                                                </pre>
                                            </div>
                                            {step.response && (
                                                <div>
                                                    <span className="text-xs text-gray-500">Response:</span>
                                                    <pre className="text-xs text-emerald-400 bg-black/30 p-2 rounded mt-1 overflow-x-auto max-h-32 overflow-y-auto">
                                                        {step.response.substring(0, 300)}{step.response.length > 300 ? '...' : ''}
                                                    </pre>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
