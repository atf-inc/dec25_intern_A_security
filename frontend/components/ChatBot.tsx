'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';
import { ChatMessage as ChatMessageType, ForensicsData } from '@/lib/types';
import ChatMessage from './ChatMessage';
import { MessageCircle, X, Send, Sparkles, Loader2, Trash2 } from 'lucide-react';

export default function ChatBot() {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState<ChatMessageType[]>([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [suggestions, setSuggestions] = useState<string[]>([]);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    // Scroll to bottom when messages change
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Focus input when chat opens
    useEffect(() => {
        if (isOpen) {
            inputRef.current?.focus();
            // Fetch suggestions on first open
            if (suggestions.length === 0) {
                fetchSuggestions();
            }
        }
    }, [isOpen, suggestions.length]);

    const fetchSuggestions = async () => {
        try {
            const data = await api.getChatSuggestions();
            setSuggestions(data.suggestions);
        } catch (error) {
            console.error('Failed to fetch suggestions:', error);
        }
    };

    const generateId = () => Math.random().toString(36).substring(2, 11);

    const handleSend = useCallback(async (messageText?: string) => {
        const text = messageText || input.trim();
        if (!text || isLoading) return;

        // Add user message
        const userMessage: ChatMessageType = {
            id: generateId(),
            role: 'user',
            content: text,
            timestamp: new Date(),
        };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsLoading(true);

        try {
            const response = await api.sendChatQuery(text);
            
            // Add assistant message
            const assistantMessage: ChatMessageType = {
                id: generateId(),
                role: 'assistant',
                content: response.content,
                render_type: response.render_type,
                data: response.data,
                timestamp: new Date(),
            };
            setMessages(prev => [...prev, assistantMessage]);
        } catch (error) {
            console.error('Chat error:', error);
            const errorMessage: ChatMessageType = {
                id: generateId(),
                role: 'assistant',
                content: 'Sorry, I encountered an error processing your request. Please try again.',
                render_type: 'text',
                timestamp: new Date(),
            };
            setMessages(prev => [...prev, errorMessage]);
        } finally {
            setIsLoading(false);
        }
    }, [input, isLoading]);

    const handleSessionClick = useCallback(async (sessionId: string) => {
        setIsLoading(true);
        
        // Add a message indicating we're analyzing
        const analyzingMessage: ChatMessageType = {
            id: generateId(),
            role: 'assistant',
            content: `Analyzing session ${sessionId.slice(0, 8)}...`,
            render_type: 'text',
            timestamp: new Date(),
        };
        setMessages(prev => [...prev, analyzingMessage]);

        try {
            const forensics = await api.getForensicsAnalysis(sessionId);
            
            // Replace the analyzing message with forensics results
            setMessages(prev => {
                const newMessages = prev.slice(0, -1);
                const forensicsMessage: ChatMessageType = {
                    id: generateId(),
                    role: 'assistant',
                    content: `Session analysis complete`,
                    render_type: 'forensics',
                    data: forensics as ForensicsData,
                    timestamp: new Date(),
                };
                return [...newMessages, forensicsMessage];
            });
        } catch (error) {
            console.error('Forensics error:', error);
            setMessages(prev => {
                const newMessages = prev.slice(0, -1);
                const errorMessage: ChatMessageType = {
                    id: generateId(),
                    role: 'assistant',
                    content: `Failed to analyze session ${sessionId}. The session may not exist or have insufficient data.`,
                    render_type: 'text',
                    timestamp: new Date(),
                };
                return [...newMessages, errorMessage];
            });
        } finally {
            setIsLoading(false);
        }
    }, []);

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    const clearMessages = () => {
        setMessages([]);
    };

    return (
        <>
            {/* Floating Button */}
            <button
                onClick={() => setIsOpen(true)}
                className={`fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/25 flex items-center justify-center hover:scale-110 transition-all duration-300 group ${isOpen ? 'hidden' : ''}`}
            >
                <MessageCircle className="w-6 h-6 text-white" />
                <span className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                
                {/* Tooltip */}
                <div className="absolute right-16 bg-gray-800 text-white text-sm px-3 py-1.5 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap border border-gray-700">
                    Ask me anything about your data
                </div>
            </button>

            {/* Chat Panel */}
            {isOpen && (
                <div className="fixed bottom-6 right-6 z-50 w-[420px] h-[600px] bg-gray-900 rounded-2xl shadow-2xl shadow-black/50 border border-gray-700 flex flex-col overflow-hidden animate-in slide-in-from-bottom-4 duration-300">
                    {/* Header */}
                    <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 border-b border-cyan-500/30">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-white/20 flex items-center justify-center">
                                <Sparkles className="w-5 h-5 text-white" />
                            </div>
                            <div>
                                <h3 className="font-semibold text-white">QuantumShield AI</h3>
                                <p className="text-xs text-cyan-100">Ask about your security data</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-1">
                            <button
                                onClick={clearMessages}
                                className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                                title="Clear chat"
                            >
                                <Trash2 className="w-4 h-4 text-white/70" />
                            </button>
                            <button
                                onClick={() => setIsOpen(false)}
                                className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                            >
                                <X className="w-5 h-5 text-white" />
                            </button>
                        </div>
                    </div>

                    {/* Messages Area */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        {messages.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center text-center px-4">
                                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-600/20 flex items-center justify-center mb-4">
                                    <Sparkles className="w-8 h-8 text-cyan-400" />
                                </div>
                                <h4 className="text-lg font-medium text-white mb-2">How can I help?</h4>
                                <p className="text-sm text-gray-400 mb-6">
                                    Ask questions about attacks, sessions, or patterns in your honeypot data.
                                </p>
                                
                                {/* Suggestions */}
                                <div className="w-full space-y-2">
                                    {suggestions.slice(0, 4).map((suggestion, i) => (
                                        <button
                                            key={i}
                                            onClick={() => handleSend(suggestion)}
                                            className="w-full text-left px-3 py-2 text-sm text-gray-300 bg-gray-800/50 hover:bg-gray-800 border border-gray-700 rounded-lg transition-colors"
                                        >
                                            {suggestion}
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            messages.map((msg) => (
                                <ChatMessage 
                                    key={msg.id} 
                                    message={msg} 
                                    onSessionClick={handleSessionClick}
                                />
                            ))
                        )}
                        
                        {/* Loading Indicator */}
                        {isLoading && (
                            <div className="flex items-center gap-3">
                                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                                    <Loader2 className="w-4 h-4 text-white animate-spin" />
                                </div>
                                <div className="bg-gray-800 border border-gray-700 rounded-2xl px-4 py-3">
                                    <div className="flex items-center gap-2">
                                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                                        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                                    </div>
                                </div>
                            </div>
                        )}
                        
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area */}
                    <div className="p-4 border-t border-gray-700 bg-gray-800/50">
                        <div className="flex items-center gap-2">
                            <input
                                ref={inputRef}
                                type="text"
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyDown={handleKeyDown}
                                placeholder="Ask about your security data..."
                                className="flex-1 bg-gray-800 border border-gray-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                                disabled={isLoading}
                            />
                            <button
                                onClick={() => handleSend()}
                                disabled={!input.trim() || isLoading}
                                className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl flex items-center justify-center hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
                            >
                                <Send className="w-4 h-4 text-white" />
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}

