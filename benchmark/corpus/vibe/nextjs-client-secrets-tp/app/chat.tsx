'use client';
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function ask(q: string) {
  const r = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: q }] });
  return r.choices[0].message.content;
}
