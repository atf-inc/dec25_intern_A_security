'use client';

import { useState } from 'react';
import { Log, SeverityLevel } from '@/lib/types';
import { format } from 'date-fns';
import { Ban, Target, ChevronDown, ChevronRight, Clock, Zap, Globe, Terminal, Shield } from 'lucide-react';
import { api } from '@/lib/api';

interface AttackColumnsProps {
    blocked: Log[];
    trapped: Log[];
}

export default function AttackColumns({ blocked, trapped }: AttackColumnsProps) {
    const [expandedSessions, setExpandedSessions] = useState<Set<string>>(new Set());
    const [sessionDetails, setSessionDetails] = useState<Map<string, Log[]>>(new Map());
    const [loadingSessions, setLoadingSessions] = useState<Set<string>>(new Set());

    const toggleSession = async (sessionId: string) => {
        if (expandedSessions.has(sessionId)) {
            // Collapse
            const newExpanded = new Set(expandedSessions);
            newExpanded.delete(sessionId);
            setExpandedSessions(newExpanded);
        } else {
            // Expand - fetch details if not cached
            if (!sessionDetails.has(sessionId)) {
                setLoadingSessions(new Set(loadingSessions).add(sessionId));
                try {
                    const details = await api.getSessionDetails(sessionId);
                    setSessionDetails(new Map(sessionDetails).set(sessionId, details.logs));
                } catch (error) {
                    console.error('Failed to fetch session details:', error);
                } finally {
                    const newLoading = new Set(loadingSessions);
                    newLoading.delete(sessionId);
                    setLoadingSessions(newLoading);
                }
            }
            const newExpanded = new Set(expandedSessions);
            newExpanded.add(sessionId);
            setExpandedSessions(newExpanded);
        }
    };

    const getSeverityColor = (severity?: SeverityLevel) => {
        switch (severity) {
            case 'CRITICAL':
                return 'bg-red-500/20 text-red-400 border-red-500/30';
            case 'HIGH':
                return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
            case 'MEDIUM':
                return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
            case 'LOW':
                return 'bg-green-500/20 text-green-400 border-green-500/30';
            default:
                return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
        }
    };

    const getAttackTypeLabel = (attackType?: string) => {
        switch (attackType) {
            case 'sqli':
                return 'SQL Injection';
            case 'xss':
                return 'XSS';
            case 'command_injection':
                return 'Command Injection';
            case 'path_traversal':
                return 'Path Traversal';
            default:
                return attackType || 'Unknown';
        }
    };

    const getAttackTypeColor = (attackType?: string) => {
        switch (attackType) {
            case 'sqli':
                return 'bg-purple-500/20 text-purple-400';
            case 'xss':
                return 'bg-pink-500/20 text-pink-400';
            case 'command_injection':
                return 'bg-red-500/20 text-red-400';
            case 'path_traversal':
                return 'bg-amber-500/20 text-amber-400';
            default:
                return 'bg-gray-500/20 text-gray-400';
        }
    };

    const getTypeIcon = (type: string) => {
        switch (type) {
            case 'command':
                return <Terminal className="w-3 h-3" />;
            case 'http_request':
            case 'trap_trigger':
            case 'trapped_interaction':
                return <Globe className="w-3 h-3" />;
            default:
                return <Shield className="w-3 h-3" />;
        }
    };

    return (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Blocked Attacks Column */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg overflow-hidden">
                <div className="flex items-center gap-2 p-4 border-b border-gray-700 bg-red-500/10">
                    <Ban className="w-5 h-5 text-red-400" />
                    <h2 className="text-lg font-semibold text-white">Blocked Attacks</h2>
                    <span className="ml-auto text-sm text-gray-400">({blocked.length})</span>
                </div>

                <div className="h-[500px] overflow-y-auto p-4 space-y-3">
                    {blocked.length === 0 ? (
                        <div className="flex items-center justify-center h-full text-gray-500">
                            No blocked attacks yet...
                        </div>
                    ) : (
                        blocked.map((log) => (
                            <div
                                key={log._id}
                                className="border border-red-700/30 rounded-lg p-4 hover:border-red-600/50 transition-all duration-200 hover:shadow-lg hover:shadow-red-500/10"
                            >
                                {/* Header */}
                                <div className="flex items-start justify-between mb-3">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        {log.severity && (
                                            <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityColor(log.severity)}`}>
                                                {log.severity}
                                            </span>
                                        )}
                                        {log.attack_type && log.attack_type !== 'unknown' && (
                                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${getAttackTypeColor(log.attack_type)}`}>
                                                {getAttackTypeLabel(log.attack_type)}
                                            </span>
                                        )}
                                    </div>
                                    <span className="text-xs text-gray-500">
                                        {format(new Date(log.timestamp), 'HH:mm:ss')}
                                    </span>
                                </div>

                                {/* ML Confidence */}
                                {log.ml_confidence !== undefined && log.ml_confidence > 0 && (
                                    <div className="mb-3">
                                        <div className="flex items-center justify-between mb-1">
                                            <span className="text-xs text-gray-500 flex items-center gap-1">
                                                <Zap className="w-3 h-3" />
                                                ML Confidence
                                            </span>
                                            <span className="text-xs text-red-400 font-medium">
                                                {(log.ml_confidence * 100).toFixed(0)}%
                                            </span>
                                        </div>
                                        <div className="w-full bg-gray-700 rounded-full h-1.5">
                                            <div
                                                className="h-1.5 rounded-full bg-red-500 transition-all duration-500"
                                                style={{ width: `${log.ml_confidence * 100}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                )}

                                {/* Request Details */}
                                <div className="space-y-2">
                                    <div className="flex items-center gap-2 text-xs text-gray-500">
                                        <span>From: {log.ip}</span>
                                        {log.http_method && log.path && (
                                            <span className="text-cyan-400 font-mono">
                                                {log.http_method} {log.path}
                                            </span>
                                        )}
                                    </div>
                                    <div className="bg-gray-900/50 rounded p-2 border border-gray-700">
                                        <code className="text-xs text-cyan-400 font-mono break-all">
                                            {log.payload.length > 150 ? `${log.payload.substring(0, 150)}...` : log.payload}
                                        </code>
                                    </div>
                                    <div className="text-xs text-red-400 font-medium">
                                        ⛔ {log.response || '403 Forbidden - Blocked'}
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>

            {/* Trapped Sessions Column */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg overflow-hidden">
                <div className="flex items-center gap-2 p-4 border-b border-gray-700 bg-amber-500/10">
                    <Target className="w-5 h-5 text-amber-400" />
                    <h2 className="text-lg font-semibold text-white">Trapped Sessions</h2>
                    <span className="ml-auto text-sm text-gray-400">({trapped.length})</span>
                </div>

                <div className="h-[500px] overflow-y-auto p-4 space-y-3">
                    {trapped.length === 0 ? (
                        <div className="flex items-center justify-center h-full text-gray-500">
                            No trapped sessions yet...
                        </div>
                    ) : (
                        trapped.map((log) => {
                            const isExpanded = expandedSessions.has(log.session_id);
                            const details = sessionDetails.get(log.session_id) || [];
                            const isLoading = loadingSessions.has(log.session_id);

                            return (
                                <div
                                    key={log._id}
                                    className="border border-amber-700/30 rounded-lg overflow-hidden hover:border-amber-600/50 transition-all duration-200"
                                >
                                    {/* Trap Trigger */}
                                    <div
                                        className="p-4 cursor-pointer hover:bg-gray-700/30"
                                        onClick={() => toggleSession(log.session_id)}
                                    >
                                        {/* Header */}
                                        <div className="flex items-start justify-between mb-3">
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <button className="p-1 hover:bg-gray-600/50 rounded">
                                                    {isExpanded ? (
                                                        <ChevronDown className="w-4 h-4 text-amber-400" />
                                                    ) : (
                                                        <ChevronRight className="w-4 h-4 text-amber-400" />
                                                    )}
                                                </button>
                                                {log.severity && (
                                                    <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityColor(log.severity)}`}>
                                                        {log.severity}
                                                    </span>
                                                )}
                                                {log.attack_type && log.attack_type !== 'unknown' && (
                                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${getAttackTypeColor(log.attack_type)}`}>
                                                        {getAttackTypeLabel(log.attack_type)}
                                                    </span>
                                                )}
                                                {(log as any).subsequent_requests > 0 && (
                                                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/20 text-cyan-400">
                                                        +{(log as any).subsequent_requests} more
                                                    </span>
                                                )}
                                            </div>
                                            <span className="text-xs text-gray-500">
                                                {format(new Date(log.timestamp), 'HH:mm:ss')}
                                            </span>
                                        </div>

                                        {/* ML Confidence */}
                                        {log.ml_confidence !== undefined && log.ml_confidence > 0 && (
                                            <div className="mb-3">
                                                <div className="flex items-center justify-between mb-1">
                                                    <span className="text-xs text-gray-500 flex items-center gap-1">
                                                        <Zap className="w-3 h-3" />
                                                        ML Confidence
                                                    </span>
                                                    <span className="text-xs text-amber-400 font-medium">
                                                        {(log.ml_confidence * 100).toFixed(0)}%
                                                    </span>
                                                </div>
                                                <div className="w-full bg-gray-700 rounded-full h-1.5">
                                                    <div
                                                        className="h-1.5 rounded-full bg-amber-500 transition-all duration-500"
                                                        style={{ width: `${log.ml_confidence * 100}%` }}
                                                    ></div>
                                                </div>
                                            </div>
                                        )}

                                        {/* Request Details */}
                                        <div className="space-y-2">
                                            <div className="flex items-center gap-2 text-xs text-gray-500">
                                                <span>From: {log.ip}</span>
                                                {log.http_method && log.path && (
                                                    <span className="text-cyan-400 font-mono">
                                                        {log.http_method} {log.path}
                                                    </span>
                                                )}
                                            </div>
                                            <div className="bg-gray-900/50 rounded p-2 border border-gray-700">
                                                <code className="text-xs text-cyan-400 font-mono break-all">
                                                    {log.payload.length > 100 ? `${log.payload.substring(0, 100)}...` : log.payload}
                                                </code>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Expanded Session Details */}
                                    {isExpanded && (
                                        <div className="border-t border-gray-700 bg-gray-900/30 p-4">
                                            {isLoading ? (
                                                <div className="text-center text-gray-500 py-4">
                                                    Loading session details...
                                                </div>
                                            ) : (
                                                <div className="space-y-2">
                                                    <div className="text-xs text-gray-400 font-semibold mb-2">
                                                        Session Activity ({details.length} requests)
                                                    </div>
                                                    {details.map((detail, idx) => (
                                                        <div
                                                            key={detail._id}
                                                            className="bg-gray-800/50 rounded p-2 border border-gray-700/50 text-xs"
                                                        >
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <span className="text-gray-500">#{idx + 1}</span>
                                                                {getTypeIcon(detail.type)}
                                                                <span className="text-gray-400">
                                                                    {format(new Date(detail.timestamp), 'HH:mm:ss')}
                                                                </span>
                                                                {detail.http_method && detail.path && (
                                                                    <span className="text-cyan-400 font-mono">
                                                                        {detail.http_method} {detail.path}
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div className="text-gray-500 font-mono truncate">
                                                                {detail.payload.substring(0, 80)}...
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        })
                    )}
                </div>
            </div>
        </div>
    );
}
