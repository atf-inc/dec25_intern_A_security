'use client';

import { Log } from '@/lib/types';
import { format } from 'date-fns';
import { AlertCircle, Terminal, Globe, Shield } from 'lucide-react';
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
                            <div className="flex items-start justify-between mb-2">
                                <div className="flex items-center gap-2">
                                    <div className={`p-1.5 rounded border ${getTypeColor(log.type)}`}>
                                        {getTypeIcon(log.type)}
                                    </div>
                                    <span className="text-sm font-medium text-white capitalize">{log.type.replace('_', ' ')}</span>
                                </div>
                                <span className="text-xs text-gray-500">
                                    {format(new Date(log.timestamp), 'HH:mm:ss')}
                                </span>
                            </div>

                            <div className="space-y-2">
                                <div>
                                    <div className="text-xs text-gray-500 mb-1">From: {log.ip}</div>
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
