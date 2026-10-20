/**
 * Model and CLI output is untrusted text. Before it is shown in a terminal, terminal escape
 * sequences and control characters (which can rewrite the screen or hide text) are removed.
 */
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_KEEP_WS_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_ANY_RE = /[\x00-\x1f\x7f-\x9f]/g;
// eslint-disable-next-line no-control-regex
const DANGEROUS_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;

/** Removes ANSI sequences and control characters, keeping newlines, tabs and carriage returns. */
export function sanitizeText(text: string): string {
  return text.replace(ANSI_RE, '').replace(CONTROL_KEEP_WS_RE, '');
}

/** Single-line variant: every control character (including newlines) becomes a space. */
export function sanitizeLine(text: string): string {
  return text.replace(ANSI_RE, '').replace(CONTROL_ANY_RE, ' ');
}

/** True when text holds a character that must never be written into a source file by a fix. */
export function hasDangerousControl(text: string): boolean {
  return DANGEROUS_RE.test(text);
}
