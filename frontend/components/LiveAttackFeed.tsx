'use client';

import { Log, SeverityLevel } from '@/lib/types';
import { format } from 'date-fns';
import { AlertCircle, Terminal, Globe, Shield, Clock, Zap } from 'lucide-react';
import { useEffect, useRef } from 'react';

interface LiveAttackFeedProps {
    logs: Log[];
}

export default function LiveAttackFeed({ logs }: LiveAttackFeedProps) {
    const feedRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (feedRef.current) {
            feedRef.current.scrollTop = 0;
        }
    }, [logs]);

    const getTypeIcon = (type: string) => {
        switch (type) {
            case 'command':
                return <Terminal className="w-4 h-4" />;
            case 'http_request':
                return <Globe className="w-4 h-4" />;
            default:
                return <Shield className="w-4 h-4" />;
        }
    };

    const getTypeColor = (type: string) => {
        switch (type) {
            case 'command':
                return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
            case 'http_request':
                return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
            default:
                return 'text-gray-400 bg-gray-500/10 border-gray-500/20';
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

    return (
        <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 p-4 border-b border-gray-700">
                <AlertCircle className="w-5 h-5 text-red-400" />
                <h2 className="text-lg font-semibold text-white">Live Attack Feed</h2>
                <div className="ml-auto flex items-center gap-2">
                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                    <span className="text-sm text-gray-400">Live</span>
                </div>
            </div>

            <div ref={feedRef} className="h-[500px] overflow-y-auto p-4 space-y-3 scroll-smooth">
                {logs.length === 0 ? (
                    <div className="flex items-center justify-center h-full text-gray-500">
                        No attacks detected yet...
                    </div>
                ) : (
                    logs.map((log) => (
                        <div
                            key={log._id}
                            className="border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-all duration-200 hover:shadow-lg hover:shadow-cyan-500/10 animate-in fade-in slide-in-from-top-2 duration-300"
                        >
                            {/* Header Row */}
                            <div className="flex items-start justify-between mb-3">
                                <div className="flex items-center gap-2 flex-wrap">
                                    <div className={`p-1.5 rounded border ${getTypeColor(log.type)}`}>
                                        {getTypeIcon(log.type)}
                                    </div>
                                    <span className="text-sm font-medium text-white capitalize">{log.type?.replace('_', ' ') || 'unknown'}</span>
                                    
                                    {/* Severity Badge */}
                                    {log.severity && (
                                        <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityColor(log.severity)}`}>
                                            {log.severity}
                                        </span>
                                    )}
                                    
                                    {/* Attack Type Badge */}
                                    {log.attack_type && log.attack_type !== 'unknown' && (
                                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getAttackTypeColor(log.attack_type)}`}>
                                            {getAttackTypeLabel(log.attack_type)}
                                        </span>
                                    )}
                                </div>
                                <span className="text-xs text-gray-500">
                                    {(() => {
                                        try {
                                            return format(new Date(log.timestamp), 'HH:mm:ss');
                                        } catch {
                                            return 'N/A';
                                        }
                                    })()}
                                </span>
                            </div>

                            {/* ML Confidence Bar */}
                            {typeof log.ml_confidence === 'number' && log.ml_confidence > 0 && (
                                <div className="mb-3">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-xs text-gray-500 flex items-center gap-1">
                                            <Zap className="w-3 h-3" />
                                            ML Confidence
                                        </span>
                                        <span className="text-xs text-cyan-400 font-medium">
                                            {(log.ml_confidence * 100).toFixed(0)}%
                                        </span>
                                    </div>
                                    <div className="w-full bg-gray-700 rounded-full h-1.5">
                                        <div 
                                            className={`h-1.5 rounded-full transition-all duration-500 ${
                                                log.ml_confidence > 0.8 ? 'bg-red-500' :
                                                log.ml_confidence > 0.5 ? 'bg-orange-500' :
                                                'bg-yellow-500'
                                            }`}
                                            style={{ width: `${log.ml_confidence * 100}%` }}
                                        ></div>
                                    </div>
                                </div>
                            )}

                            {/* Request Details */}
                            <div className="space-y-2">
                                <div>
                                    <div className="flex items-center gap-2 text-xs text-gray-500 mb-1">
                                        <span>From: {log.ip}</span>
                                        {log.http_method && log.path && (
                                            <span className="text-cyan-400 font-mono">
                                                {log.http_method} {log.path}
                                            </span>
                                        )}
                                        {typeof log.response_time_ms === 'number' && (
                                            <span className="flex items-center gap-1 text-gray-400">
                                                <Clock className="w-3 h-3" />
                                                {log.response_time_ms.toFixed(0)}ms
                                            </span>
                                        )}
                                    </div>
                                    <div className="bg-gray-900/50 rounded p-2 border border-gray-700">
                                        <code className="text-xs text-cyan-400 font-mono break-all">
                                            {log.payload.length > 200 ? `${log.payload.substring(0, 200)}...` : log.payload}
                                        </code>
                                    </div>
                                </div>

                                {log.response && (
                                    <div>
                                        <div className="text-xs text-gray-500 mb-1">Response:</div>
                                        <div className="bg-gray-900/50 rounded p-2 border border-gray-700">
                                            <code className="text-xs text-emerald-400 font-mono break-all">
                                                {log.response.length > 150 ? `${log.response.substring(0, 150)}...` : log.response}
                                            </code>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
