/**
 * Parse a model's fix reply into { explanation, newCode }.
 *
 * Prefers a fenced code block — reliable for code models, which tend to emit
 * literal newlines/quotes that break JSON-with-embedded-code. Falls back to
 * STRICT JSON for models that follow that format.
 */
export interface FixSuggestion {
  explanation: string;
  newCode: string;
}

export function extractFix(text: string): FixSuggestion | null {
  const fence = /```[a-zA-Z0-9]*\r?\n?([\s\S]*?)```/.exec(text);
  if (fence && fence[1]) {
    const newCode = fence[1].replace(/\s+$/, '');
    const before = text.slice(0, fence.index).replace(/^\s*(explanation|fix)\s*[:.-]?\s*/i, '').trim();
    const explanation = (before.split('\n').find((l) => l.trim().length) ?? '').slice(0, 300);
    if (newCode.trim()) return { explanation, newCode };
  }

  // Fallback: STRICT JSON { explanation, newCode }.
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(text.slice(start, end + 1)) as Partial<FixSuggestion>;
      if (typeof obj.newCode === 'string') {
        return { explanation: typeof obj.explanation === 'string' ? obj.explanation : '', newCode: obj.newCode };
      }
    } catch {
      /* fall through */
    }
  }
  return null;
}
