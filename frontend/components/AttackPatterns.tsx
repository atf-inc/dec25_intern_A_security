'use client';

import { AttackPattern } from '@/lib/types';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { Shield } from 'lucide-react';

interface AttackPatternsProps {
    attackTypes: AttackPattern[];
}

const COLORS = ['#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'];

export default function AttackPatterns({ attackTypes }: AttackPatternsProps) {
    const data = attackTypes.map((pattern) => ({
        name: pattern._id || 'Unknown',
        value: pattern.count,
    }));

    return (
        <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-lg overflow-hidden">
            <div className="flex items-center gap-2 p-4 border-b border-gray-700">
                <Shield className="w-5 h-5 text-yellow-400" />
                <h2 className="text-lg font-semibold text-white">Attack Pattern Distribution</h2>
            </div>

            <div className="p-6">
                {data.length === 0 ? (
                    <div className="flex items-center justify-center h-64 text-gray-500">
                        No attack data available
                    </div>
                ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <ResponsiveContainer width="100%" height={300}>
                            <PieChart>
                                <Pie
                                    data={data}
                                    cx="50%"
                                    cy="50%"
                                    labelLine={false}
                                    label={({ name, percent }) => {
                                        const p = typeof percent === 'number' ? percent : 0;
                                        return `${name || 'Unknown'}: ${(p * 100).toFixed(0)}%`;
                                    }}
                                    outerRadius={80}
                                    fill="#8884d8"
                                    dataKey="value"
                                >
                                    {data.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
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

                        <div className="space-y-3">
                            {data.map((item, index) => (
                                <div key={index} className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg border border-gray-700">
                                    <div className="flex items-center gap-3">
                                        <div
                                            className="w-4 h-4 rounded"
                                            style={{ backgroundColor: COLORS[index % COLORS.length] }}
                                        ></div>
                                        <span className="text-sm font-medium text-white">{item.name}</span>
                                    </div>
                                    <span className="text-sm font-bold text-cyan-400">{item.value.toLocaleString()}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
