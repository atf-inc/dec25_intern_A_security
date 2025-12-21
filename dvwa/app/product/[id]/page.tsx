'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'

interface Product {
    id: number
    name: string
    description: string
    price: number
    image: string
    stock: number
}

interface Review {
    id: number
    rating: number
    comment: string
    username: string
    created_at: string
}

export default function ProductPage() {
    const params = useParams()
    const [product, setProduct] = useState<Product | null>(null)
    const [reviews, setReviews] = useState<Review[]>([])
    const [rating, setRating] = useState(5)
    const [comment, setComment] = useState('')
    const [result, setResult] = useState<any>(null)

    useEffect(() => {
        fetchProduct()
        fetchReviews()
    }, [params.id])

    const fetchProduct = async () => {
        const res = await fetch(`/api/products/${params.id}`)
        const data = await res.json()
        setProduct(data.product)
    }

    const fetchReviews = async () => {
        const res = await fetch(`/api/reviews?product_id=${params.id}`)
        const data = await res.json()
        setReviews(data.reviews || [])
    }

    const handleSubmitReview = async (e: React.FormEvent) => {
        e.preventDefault()
        const user = JSON.parse(localStorage.getItem('user') || '{"id": 1, "username": "guest"}')

        const res = await fetch('/api/reviews', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                product_id: params.id,
                user_id: user.id || 1,
                rating,
                comment
            })
        })

        const data = await res.json()
        setResult(data)
        if (data.success) {
            fetchReviews()
            setComment('')
        }
    }

    if (!product) return <div className="p-8">Loading...</div>

    return (
        <div className="min-h-screen bg-gray-50">
            <header className="bg-white shadow-sm">
                <div className="max-w-7xl mx-auto px-4 py-4">
                    <Link href="/" className="text-blue-600 hover:text-blue-700">← Back to Shop</Link>
                </div>
            </header>

            <div className="max-w-7xl mx-auto px-4 py-8">
                <div className="bg-white rounded-lg shadow-md p-8 mb-8">
                    <div className="grid md:grid-cols-2 gap-8">
                        <div className="h-96 bg-gradient-to-br from-gray-200 to-gray-300 rounded-lg flex items-center justify-center overflow-hidden">
                            <img 
                                src={product.image} 
                                alt={product.name}
                                className="w-full h-full object-cover"
                                onError={(e) => {
                                    (e.target as HTMLImageElement).style.display = 'none';
                                    e.currentTarget.parentElement!.innerHTML = `<span class="text-gray-500">${product.name}</span>`;
                                }}
                            />
                        </div>
                        <div>
                            <h1 className="text-3xl font-bold text-gray-900 mb-4">{product.name}</h1>
                            <p className="text-gray-600 mb-6">{product.description}</p>
                            <div className="text-4xl font-bold text-blue-600 mb-4">${product.price}</div>
                            <p className="text-gray-500 mb-6">{product.stock} units available</p>
                            <button className="w-full bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700">
                                Add to Cart
                            </button>
                        </div>
                    </div>
                </div>

                {/* Reviews Section */}
                <div className="bg-white rounded-lg shadow-md p-8">
                    <h2 className="text-2xl font-bold mb-6">Customer Reviews</h2>

                    {/* Submit Review Form */}
                    <form onSubmit={handleSubmitReview} className="mb-8 p-6 bg-gray-50 rounded-lg">
                        <h3 className="font-semibold mb-4">Write a Review</h3>
                        <div className="mb-4">
                            <label className="block text-sm font-medium mb-2">Rating</label>
                            <select
                                value={rating}
                                onChange={(e) => setRating(Number(e.target.value))}
                                className="w-full px-3 py-2 border rounded-md"
                            >
                                {[5, 4, 3, 2, 1].map(r => (
                                    <option key={r} value={r}>{r} Stars</option>
                                ))}
                            </select>
                        </div>
                        <div className="mb-4">
                            <label className="block text-sm font-medium mb-2">Comment</label>
                            <textarea
                                value={comment}
                                onChange={(e) => setComment(e.target.value)}
                                className="w-full px-3 py-2 border rounded-md"
                                rows={4}
                                required
                            />
                        </div>
                        <button type="submit" className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700">
                            Submit Review
                        </button>

                        <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded">
                            <p className="text-sm text-yellow-800">
                                <strong>⚠️ XSS Vulnerability:</strong> Try: <code className="bg-yellow-100 px-1">&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                            </p>
                        </div>
                    </form>

                    {result && (
                        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-md">
                            <pre className="text-sm">{JSON.stringify(result, null, 2)}</pre>
                        </div>
                    )}

                    {/* Display Reviews */}
                    <div className="space-y-4">
                        {reviews.map((review) => (
                            <div key={review.id} className="border-b pb-4">
                                <div className="flex items-center gap-2 mb-2">
                                    <span className="font-semibold">{review.username}</span>
                                    <span className="text-yellow-500">{'★'.repeat(review.rating)}</span>
                                </div>
                                {/* VULNERABLE: XSS - comment is rendered without sanitization */}
                                <div dangerouslySetInnerHTML={{ __html: review.comment }} />
                                <p className="text-sm text-gray-500 mt-2">{new Date(review.created_at).toLocaleDateString()}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div >
        </div >
    )
}
