'use client'
import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

export default function Home() {
  const [todos, setTodos] = useState<any[]>([])
  useEffect(() => { supabase.from('todos').select('*').then(({ data }) => setTodos(data ?? [])) }, [])
  return <ul>{todos.map((t) => <li key={t.id}>{t.title}</li>)}</ul>
}
