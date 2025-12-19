'use client';

import { Stats } from '@/lib/types';
import { Activity, Shield, Users, Zap, Database, Brain } from 'lucide-react';

interface StatsCardsProps {
    stats: Stats | null;
}

export default function StatsCards({ stats }: StatsCardsProps) {
    if (!stats) {
        return (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => (
                    <div key={i} className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6 animate-pulse">
                        <div className="h-12 bg-gray-700 rounded"></div>
                    </div>
                ))}
            </div>
        );
    }

    const cards = [
        {
            title: 'Total Interactions',
            value: stats.total_interactions.toLocaleString(),
            icon: Activity,
            color: 'text-cyan-400',
            bgColor: 'bg-cyan-500/10',
        },
        {
            title: 'Active Sessions',
            value: stats.active_sessions.toString(),
            icon: Users,
            color: 'text-emerald-400',
            bgColor: 'bg-emerald-500/10',
        },
        {
            title: 'Recent Activity (24h)',
            value: stats.recent_activity_24h.toLocaleString(),
            icon: Zap,
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
        },
        {
            title: 'Cache Hit Rate',
            value: stats.cache.hit_rate,
            icon: Database,
            color: 'text-purple-400',
            bgColor: 'bg-purple-500/10',
        },
    ];

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {cards.map((card, index) => (
                <div
                    key={index}
                    className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6 hover:border-gray-600 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/20"
                >
                    <div className="flex items-center justify-between mb-4">
                        <div className={`p-3 rounded-lg ${card.bgColor}`}>
                            <card.icon className={`w-6 h-6 ${card.color}`} />
                        </div>
                    </div>
                    <div className="text-3xl font-bold text-white mb-1">{card.value}</div>
                    <div className="text-sm text-gray-400">{card.title}</div>
                </div>
            ))}

            {/* Additional LLM Stats Card */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg p-6 hover:border-gray-600 transition-all duration-300 md:col-span-2 lg:col-span-4">
                <div className="flex items-center gap-4">
                    <div className="p-3 rounded-lg bg-blue-500/10">
                        <Brain className="w-6 h-6 text-blue-400" />
                    </div>
                    <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <div className="text-sm text-gray-400">LLM Model</div>
                            <div className="text-lg font-semibold text-white">{stats.llm.model}</div>
                        </div>
                        <div>
                            <div className="text-sm text-gray-400">Total LLM Requests</div>
                            <div className="text-lg font-semibold text-white">{stats.llm.total_requests.toLocaleString()}</div>
                        </div>
                        <div>
                            <div className="text-sm text-gray-400">Cache Efficiency</div>
                            <div className="text-lg font-semibold text-white">
                                {stats.cache.hits} hits / {stats.cache.misses} misses
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
