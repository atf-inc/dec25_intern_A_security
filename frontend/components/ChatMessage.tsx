'use client';

import { ChatMessage as ChatMessageType, ChartDataPoint, ForensicsData } from '@/lib/types';
import { BarChart, Bar, PieChart, Pie, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { User, Bot, Terminal, AlertTriangle, Shield, ChevronRight } from 'lucide-react';

interface ChatMessageProps {
    message: ChatMessageType;
    onSessionClick?: (sessionId: string) => void;
}

const CHART_COLORS = ['#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'];

export default function ChatMessage({ message, onSessionClick }: ChatMessageProps) {
    const isUser = message.role === 'user';

    // Detect and make session IDs clickable
    const renderTextWithSessionLinks = (text: string) => {
        // Match common session ID patterns (UUIDs)
        const sessionIdPattern = /([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi;
        const parts = text.split(sessionIdPattern);

        return parts.map((part, index) => {
            if (sessionIdPattern.test(part)) {
                return (
                    <button
                        key={index}
                        onClick={() => onSessionClick?.(part)}
                        className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 font-mono text-sm"
                    >
                        {part}
                    </button>
                );
            }
            return <span key={index}>{part}</span>;
        });
    };

    const renderContent = () => {
        switch (message.render_type) {
            case 'bar_chart':
                return renderBarChart();
            case 'pie_chart':
                return renderPieChart();
            case 'line_chart':
                return renderLineChart();
            case 'table':
                return renderTable();
            case 'forensics':
                return renderForensics();
            default:
                return renderText();
        }
    };

    const renderText = () => (
        <div className="text-sm text-gray-200 whitespace-pre-wrap">
            {renderTextWithSessionLinks(message.content)}
        </div>
    );

    const renderBarChart = () => {
        const data = message.data as ChartDataPoint[];
        if (!data || data.length === 0) return renderText();

        return (
            <div className="space-y-3">
                <p className="text-sm text-gray-200">{message.content}</p>
                <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700">
                    <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={data} layout="vertical">
                            <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                            <YAxis 
                                type="category" 
                                dataKey="name" 
                                tick={{ fill: '#9ca3af', fontSize: 11 }} 
                                width={100}
                            />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: '#1f2937',
                                    border: '1px solid #374151',
                                    borderRadius: '0.5rem',
                                    color: '#fff',
                                }}
                            />
                            <Bar dataKey="value" fill="#06b6d4" radius={[0, 4, 4, 0]}>
                                {data.map((_, index) => (
                                    <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>
        );
    };

    const renderPieChart = () => {
        const data = message.data as ChartDataPoint[];
        if (!data || data.length === 0) return renderText();

        return (
            <div className="space-y-3">
                <p className="text-sm text-gray-200">{message.content}</p>
                <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700">
                    <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                            <Pie
                                data={data}
                                cx="50%"
                                cy="50%"
                                labelLine={false}
                                label={({ name, percent }) => `${name}: ${((percent || 0) * 100).toFixed(0)}%`}
                                outerRadius={70}
                                dataKey="value"
                            >
                                {data.map((_, index) => (
                                    <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: '#1f2937',
                                    border: '1px solid #374151',
                                    borderRadius: '0.5rem',
                                    color: '#fff',
                                }}
                            />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>
        );
    };

    const renderLineChart = () => {
        const data = message.data as ChartDataPoint[];
        if (!data || data.length === 0) return renderText();

        return (
            <div className="space-y-3">
                <p className="text-sm text-gray-200">{message.content}</p>
                <div className="bg-gray-900/50 rounded-lg p-4 border border-gray-700">
                    <ResponsiveContainer width="100%" height={200}>
                        <LineChart data={data}>
                            <XAxis 
                                dataKey="name" 
                                tick={{ fill: '#9ca3af', fontSize: 10 }} 
                                angle={-45}
                                textAnchor="end"
                                height={60}
                            />
                            <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: '#1f2937',
                                    border: '1px solid #374151',
                                    borderRadius: '0.5rem',
                                    color: '#fff',
                                }}
                            />
                            <Line 
                                type="monotone" 
                                dataKey="value" 
                                stroke="#06b6d4" 
                                strokeWidth={2}
                                dot={{ fill: '#06b6d4', strokeWidth: 2 }}
                            />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </div>
        );
    };

    const renderTable = () => {
        const data = message.data as Record<string, unknown>[];
        if (!data || data.length === 0) return renderText();

        // Get column headers from first row
        const columns = Object.keys(data[0]).filter(key => key !== 'id' && key !== '_id');

        return (
            <div className="space-y-3">
                <p className="text-sm text-gray-200">{message.content}</p>
                <div className="bg-gray-900/50 rounded-lg border border-gray-700 overflow-hidden">
                    <div className="overflow-x-auto max-h-64 overflow-y-auto">
                        <table className="w-full text-xs">
                            <thead className="bg-gray-800 sticky top-0">
                                <tr>
                                    {columns.slice(0, 5).map((col) => (
                                        <th key={col} className="px-3 py-2 text-left text-gray-400 font-medium">
                                            {col.replace(/_/g, ' ')}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-700">
                                {data.slice(0, 10).map((row, i) => (
                                    <tr key={i} className="hover:bg-gray-800/50">
                                        {columns.slice(0, 5).map((col) => (
                                            <td key={col} className="px-3 py-2 text-gray-300 truncate max-w-[150px]">
                                                {col === 'session_id' ? (
                                                    <button
                                                        onClick={() => onSessionClick?.(String(row[col]))}
                                                        className="text-cyan-400 hover:text-cyan-300 underline"
                                                    >
                                                        {String(row[col]).slice(0, 8)}...
                                                    </button>
                                                ) : (
                                                    String(row[col] ?? '-')
                                                )}
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {data.length > 10 && (
                        <div className="px-3 py-2 bg-gray-800 text-xs text-gray-400">
                            Showing 10 of {data.length} results
                        </div>
                    )}
                </div>
            </div>
        );
    };

    const renderForensics = () => {
        const forensics = message.data as ForensicsData;
        if (!forensics) return renderText();

        const threatColors: Record<string, string> = {
            'Low': 'text-green-400 bg-green-500/10 border-green-500/30',
            'Medium': 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
            'High': 'text-orange-400 bg-orange-500/10 border-orange-500/30',
            'Critical': 'text-red-400 bg-red-500/10 border-red-500/30',
        };

        return (
            <div className="space-y-4">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-cyan-400" />
                        <span className="text-sm font-medium text-white">Session Forensics</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${threatColors[forensics.threat_level] || threatColors['Medium']}`}>
                        {forensics.threat_level}
                    </span>
                </div>

                {/* Session Info */}
                <div className="bg-gray-900/50 rounded-lg p-3 border border-gray-700 space-y-1">
                    <div className="flex items-center gap-2 text-xs">
                        <span className="text-gray-400">Session:</span>
                        <span className="font-mono text-cyan-400">{forensics.session_id.slice(0, 8)}...</span>
                    </div>
                    {forensics.ip_address && (
                        <div className="flex items-center gap-2 text-xs">
                            <span className="text-gray-400">IP:</span>
                            <span className="text-gray-200">{forensics.ip_address}</span>
                        </div>
                    )}
                    <div className="flex items-center gap-2 text-xs">
                        <span className="text-gray-400">Intent:</span>
                        <span className="text-orange-400 font-medium">{forensics.intent}</span>
                    </div>
                </div>

                {/* Command History */}
                {forensics.command_history.length > 0 && (
                    <div className="bg-gray-950 rounded-lg border border-gray-700 overflow-hidden">
                        <div className="px-3 py-2 bg-gray-800 border-b border-gray-700 text-xs text-gray-400 flex items-center gap-2">
                            <Terminal className="w-3 h-3" />
                            Command History
                        </div>
                        <div className="p-3 space-y-2 max-h-40 overflow-y-auto font-mono text-xs">
                            {forensics.command_history.slice(-5).map((cmd, i) => (
                                <div key={i} className="space-y-1">
                                    <div className="flex items-center gap-2">
                                        <ChevronRight className="w-3 h-3 text-green-400" />
                                        <span className="text-green-400">{cmd.cmd}</span>
                                    </div>
                                    {cmd.res && (
                                        <div className="pl-5 text-gray-500 truncate">{cmd.res.slice(0, 100)}</div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Analysis */}
                <div className="bg-gray-900/50 rounded-lg p-3 border border-gray-700">
                    <div className="flex items-center gap-2 mb-2">
                        <Shield className="w-4 h-4 text-blue-400" />
                        <span className="text-xs font-medium text-gray-300">Analysis</span>
                    </div>
                    <p className="text-xs text-gray-300 leading-relaxed">{forensics.analysis}</p>
                </div>

                {/* Blocked Actions */}
                {forensics.blocked_actions.length > 0 && (
                    <div className="bg-red-500/5 rounded-lg p-3 border border-red-500/20">
                        <div className="flex items-center gap-2 mb-2">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            <span className="text-xs font-medium text-red-400">Blocked by Honeypot</span>
                        </div>
                        <ul className="space-y-1">
                            {forensics.blocked_actions.map((action, i) => (
                                <li key={i} className="text-xs text-gray-400 flex items-center gap-2">
                                    <span className="w-1 h-1 bg-red-400 rounded-full" />
                                    {action}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className={`flex gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
            {/* Avatar */}
            <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                isUser 
                    ? 'bg-gradient-to-br from-purple-500 to-pink-600' 
                    : 'bg-gradient-to-br from-cyan-500 to-blue-600'
            }`}>
                {isUser ? <User className="w-4 h-4 text-white" /> : <Bot className="w-4 h-4 text-white" />}
            </div>

            {/* Message Bubble */}
            <div className={`flex-1 max-w-[85%] ${isUser ? 'flex justify-end' : ''}`}>
                <div className={`rounded-2xl px-4 py-3 ${
                    isUser 
                        ? 'bg-gradient-to-br from-purple-600 to-pink-600 text-white' 
                        : 'bg-gray-800 border border-gray-700'
                }`}>
                    {renderContent()}
                </div>
                <div className={`text-xs text-gray-500 mt-1 ${isUser ? 'text-right' : ''}`}>
                    {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
            </div>
        </div>
    );
}

