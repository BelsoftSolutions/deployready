/**
 * Interactive, step-by-step fix walkthrough.
 *
 * Phase 1.5 (per the spec's "Strategy Update"): agentic fix application
 * (propose → diff → approve → apply → verify) is deferred. This module is the
 * extension point — the surrounding architecture (findings, checklist) already
 * feeds it. For the MVP we present the recommendation; we never auto-edit files.
 */
import type { Finding } from '../types';

export class FixWalker {
  /**
   * Return the human-readable fix guidance for a finding. In Phase 1.5 this
   * becomes an interactive flow backed by agent/FixManager + agent/FileEditor.
   */
  static guidanceFor(finding: Finding): string {
    const loc = finding.endpoint ?? (finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : 'project');
    return `Fix for "${finding.title}" (${loc}):\n${finding.recommendation}`;
  }
}
