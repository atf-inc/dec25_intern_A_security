'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'

interface Order {
    id: number
    product_name: string
    quantity: number
    total: number
    status: string
    created_at: string
}

export default function ProfilePage() {
    const [user, setUser] = useState<any>(null)
    const [orders, setOrders] = useState<Order[]>([])
    const [userId, setUserId] = useState('')
    const [result, setResult] = useState<any>(null)

    useEffect(() => {
        const storedUser = localStorage.getItem('user')
        if (storedUser) {
            const userData = JSON.parse(storedUser)
            setUser(userData)
            setUserId(userData.id?.toString() || '1')
            fetchOrders(userData.id || 1)
        }
    }, [])

    const fetchOrders = async (id: number | string) => {
        try {
            // VULNERABLE: IDOR - can view any user's orders by changing ID
            const res = await fetch(`/api/orders?user_id=${id}`)
            const data = await res.json()
            setOrders(data.orders || [])
            setResult(data)
        } catch (error) {
            console.error('Error fetching orders:', error)
        }
    }

    const handleViewOrders = () => {
        fetchOrders(userId)
    }

    if (!user) {
        return (
            <div className="min-h-screen bg-gray-50 flex items-center justify-center">
                <div className="text-center">
                    <p className="text-gray-600 mb-4">Please log in first</p>
                    <Link href="/login" className="text-blue-600 hover:text-blue-700">
                        Go to Login
                    </Link>
                </div>
            </div>
        )
    }

    return (
        <div className="min-h-screen bg-gray-50">
            <header className="bg-white shadow-sm">
                <div className="max-w-7xl mx-auto px-4 py-4">
                    <Link href="/" className="text-blue-600 hover:text-blue-700">← Back to Shop</Link>
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-4 py-8">
                <div className="bg-white rounded-lg shadow-md p-8 mb-8">
                    <h1 className="text-3xl font-bold mb-6">My Profile</h1>
                    <div className="grid md:grid-cols-2 gap-6">
                        <div>
                            <p className="text-gray-600 mb-2"><strong>Username:</strong> {user.username}</p>
                            <p className="text-gray-600 mb-2"><strong>Email:</strong> {user.email}</p>
                            <p className="text-gray-600"><strong>User ID:</strong> {user.id}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white rounded-lg shadow-md p-8">
                    <h2 className="text-2xl font-bold mb-6">My Orders</h2>

                    {/* IDOR Vulnerability Demo */}
                    <div className="mb-6 p-4 bg-yellow-50 border border-yellow-200 rounded-md">
                        <p className="text-sm text-yellow-800 mb-3">
                            <strong>⚠️ IDOR Vulnerability:</strong> Try viewing other users' orders
                        </p>
                        <div className="flex gap-2">
                            <input
                                type="number"
                                value={userId}
                                onChange={(e) => setUserId(e.target.value)}
                                className="px-3 py-2 border rounded-md"
                                placeholder="User ID"
                            />
                            <button
                                onClick={handleViewOrders}
                                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                            >
                                View Orders
                            </button>
                        </div>
                        <p className="text-xs text-gray-600 mt-2">
                            Hint: Try user_id=2 or user_id=3 to see other users' orders
                        </p>
                    </div>

                    {result && result.vulnerable && (
                        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-md">
                            <p className="text-sm text-red-800">
                                <strong>Security Issue:</strong> You can access orders from user_id={userId} without authorization!
                            </p>
                        </div>
                    )}

                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-4 py-3 text-left text-sm font-semibold">Order ID</th>
                                    <th className="px-4 py-3 text-left text-sm font-semibold">Product</th>
                                    <th className="px-4 py-3 text-left text-sm font-semibold">Quantity</th>
                                    <th className="px-4 py-3 text-left text-sm font-semibold">Total</th>
                                    <th className="px-4 py-3 text-left text-sm font-semibold">Status</th>
                                    <th className="px-4 py-3 text-left text-sm font-semibold">Date</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y">
                                {orders.map((order) => (
                                    <tr key={order.id}>
                                        <td className="px-4 py-3">#{order.id}</td>
                                        <td className="px-4 py-3">{order.product_name}</td>
                                        <td className="px-4 py-3">{order.quantity}</td>
                                        <td className="px-4 py-3">${order.total}</td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-1 rounded text-sm ${order.status === 'delivered' ? 'bg-green-100 text-green-800' :
                                                    order.status === 'shipped' ? 'bg-blue-100 text-blue-800' :
                                                        'bg-yellow-100 text-yellow-800'
                                                }`}>
                                                {order.status}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">{new Date(order.created_at).toLocaleDateString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {orders.length === 0 && (
                        <p className="text-center text-gray-500 py-8">No orders found</p>
                    )}
                </div>
            </div>
        </div>
    )
}
