'use client'
import OpenAI from 'openai'

const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
})

export default function Chat() {
  async function ask(q: string) {
    const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: q }] })
    return r.choices[0].message.content
  }
  return <button onClick={() => ask('hi')}>Ask</button>
}
