/**
 * Confidence-tiered secret DETECTION (for findings). Separate from redaction, which is
 * deliberately more aggressive: detection must avoid false alarms, redaction must never
 * leak. Both use the same span finder (./scan).
 */
import type { Confidence } from './detectors';
import { privateKeyBlocks } from './multiline';
import { detectionConfidence, isHighEntropyToken, scanLine } from './scan';

export interface SecretHit {
  /** Detector id, e.g. `aws-access-key-id`, `supabase-service-role-jwt`, `kv-secret-named`. */
  id: string;
  confidence: Confidence;
  /** 1-based line number within the scanned text. */
  line: number;
}

const MAX_LINE = 4000;

/** Every secret detected in `text`, one entry per (line, detector). Public keys are excluded. */
export function detectSecrets(text: string): SecretHit[] {
  const hits: SecretHit[] = [];
  if (!text) return hits;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = raw.length > MAX_LINE ? raw.slice(0, MAX_LINE) : raw;
    const seen = new Set<string>();
    const spans = scanLine(line);
    // A shape match inside a kv value (e.g. `apiKey = "sk-…"`) is the stronger signal.
    for (const s of spans) {
      const conf = detectionConfidence(s);
      if (!conf) continue;
      const id = s.kind === 'kv' && isHighEntropyToken(s.value) ? 'generic-high-entropy' : s.id;
      if (seen.has(id)) continue;
      seen.add(id);
      hits.push({ id, confidence: conf, line: i + 1 });
    }
  }
  // A private-key body is multi-line; its header line is already a shape hit, but an
  // escaped one-line key (service-account JSON) is caught here too.
  if (!hits.some((h) => h.id === 'private-key')) {
    for (const b of privateKeyBlocks(text)) {
      hits.push({ id: 'private-key', confidence: 'high', line: text.slice(0, b.start).split('\n').length });
    }
  }
  return hits;
}

/** Highest confidence across the text, or null when nothing secret-like is present. */
export function detectSecretConfidence(text: string): Confidence | null {
  let low = false;
  for (const h of detectSecrets(text)) {
    if (h.confidence === 'high') return 'high';
    low = true;
  }
  return low ? 'low' : null;
}
