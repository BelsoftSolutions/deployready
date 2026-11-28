import React from 'react'
import DOMPurify from 'dompurify'

export function Comment({ comment }) {
  return (
    <div className="comment">
      <strong>{comment.author}</strong>
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />
      <p>{comment.title}</p>
    </div>
  )
}
