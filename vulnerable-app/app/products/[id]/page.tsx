'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'

export default function ProductDetailPage() {
  const params = useParams()
  const productId = params.id as string
  const [product, setProduct] = useState<any>(null)
  const [reviews, setReviews] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [reviewAuthor, setReviewAuthor] = useState('')
  const [reviewRating, setReviewRating] = useState('5')
  const [reviewComment, setReviewComment] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    loadProduct()
    loadReviews()
  }, [productId])

  const loadProduct = async () => {
    try {
      const response = await fetch(`/api/products/${productId}`)
      const data = await response.json()
      setProduct(data.product)
    } catch (error) {
      console.error('Error loading product:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadReviews = async () => {
    try {
      const response = await fetch(`/api/reviews?productId=${productId}`)
      const data = await response.json()
      setReviews(data.reviews || [])
    } catch (error) {
      console.error('Error loading reviews:', error)
    }
  }

  const submitReview = async () => {
    setSubmitting(true)
    try {
      const response = await fetch('/api/reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          productId: productId,
          author: reviewAuthor,
          rating: reviewRating,
          comment: reviewComment
        })
      })
      const data = await response.json()
      if (data.success) {
        setReviewAuthor('')
        setReviewComment('')
        setReviewRating('5')
        loadReviews()
      }
    } catch (error) {
      console.error('Error submitting review:', error)
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return (
      <div className="container">
        <div className="alert alert-info">Loading product...</div>
      </div>
    )
  }

  if (!product) {
    return (
      <div className="container">
        <div className="alert alert-danger">Product not found</div>
        <Link href="/products" className="btn btn-secondary">Back to Products</Link>
      </div>
    )
  }

  return (
    <div className="container">
      <Link href="/products" className="btn btn-secondary" style={{ marginBottom: '1rem' }}>
        ← Back to Products
      </Link>

      <div className="product-detail">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          <div>
            <div className="product-detail-image" style={{ 
              fontSize: '10rem', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              background: '#f0f0f0'
            }}>
              {product.image || '📦'}
            </div>
          </div>
          <div>
            <h1 style={{ fontSize: '2rem', marginBottom: '1rem' }}>{product.name}</h1>
            <div className="product-price" style={{ fontSize: '2rem', marginBottom: '1rem' }}>
              ${product.price.toFixed(2)}
            </div>
            <div className="product-description" style={{ marginBottom: '2rem', fontSize: '1.1rem' }}>
              {product.description}
            </div>
            <div style={{ marginBottom: '1rem' }}>
              <strong>Category:</strong> {product.category}
            </div>
            <div style={{ marginBottom: '2rem' }}>
              <strong>Stock:</strong> {product.stock} available
            </div>
            <button className="btn btn-primary" style={{ fontSize: '1.2rem', padding: '1rem 2rem' }}>
              Add to Cart
            </button>
          </div>
        </div>
      </div>

      <div style={{ marginTop: '3rem' }}>
        <h2>Customer Reviews</h2>
        
        <div className="alert alert-warning">
          <strong>⚠️ Vulnerability:</strong> Reviews are vulnerable to stored XSS attacks.
          Try submitting: <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
        </div>

        <div style={{ background: 'white', padding: '2rem', borderRadius: '10px', marginBottom: '2rem', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
          <h3>Write a Review</h3>
          <div className="form-group">
            <label>Your Name:</label>
            <input
              type="text"
              value={reviewAuthor}
              onChange={(e) => setReviewAuthor(e.target.value)}
              placeholder="Your name"
            />
          </div>
          <div className="form-group">
            <label>Rating:</label>
            <select value={reviewRating} onChange={(e) => setReviewRating(e.target.value)}>
              <option value="5">5 Stars</option>
              <option value="4">4 Stars</option>
              <option value="3">3 Stars</option>
              <option value="2">2 Stars</option>
              <option value="1">1 Star</option>
            </select>
          </div>
          <div className="form-group">
            <label>Your Review (Vulnerable to XSS):</label>
            <textarea
              value={reviewComment}
              onChange={(e) => setReviewComment(e.target.value)}
              placeholder="Write your review here..."
              rows={5}
            />
          </div>
          <button 
            onClick={submitReview} 
            className="btn btn-primary"
            disabled={submitting}
          >
            {submitting ? 'Submitting...' : 'Submit Review'}
          </button>
        </div>

        <div>
          {reviews.length > 0 ? (
            reviews.map(review => (
              <div key={review.id} className="review">
                <div className="review-author">{review.author}</div>
                <div className="review-rating">
                  {'⭐'.repeat(review.rating)}
                </div>
                <div className="review-content">
                  {/* VULNERABLE: Direct HTML rendering - XSS possible */}
                  <div dangerouslySetInnerHTML={{ __html: review.comment }} />
                </div>
                <div style={{ fontSize: '0.9rem', color: '#666', marginTop: '0.5rem' }}>
                  {new Date(review.date).toLocaleDateString()}
                </div>
              </div>
            ))
          ) : (
            <div className="alert alert-info">No reviews yet. Be the first to review!</div>
          )}
        </div>
      </div>
    </div>
  )
}

