/**
 * Animated welcome banner. ASCII "DEPLOY" wordmark with a line-by-line gradient
 * reveal and a "READY" accent, so the brand reads "DeployReady".
 *
 * Degrades gracefully:
 * - No TTY (piped/CI): prints instantly, no delays.
 * - Narrow terminals (< 64 cols): a compact boxed logo that never wraps.
 *
 * The wordmark is assembled from per-letter glyph blocks (each padded to its own
 * width and joined column-wise) so the art stays aligned without hand-counting.
 */
import chalk from 'chalk';

// ANSI Shadow glyphs, 6 rows per letter.
const GLYPHS: Record<string, string[]> = {
  D: ['██████╗ ', '██╔══██╗', '██║  ██║', '██║  ██║', '██████╔╝', '╚═════╝ '],
  E: ['███████╗', '██╔════╝', '█████╗  ', '██╔══╝  ', '███████╗', '╚══════╝'],
  P: ['██████╗ ', '██╔══██╗', '██████╔╝', '██╔═══╝ ', '██║     ', '╚═╝     '],
  L: ['██╗     ', '██║     ', '██║     ', '██║     ', '███████╗', '╚══════╝'],
  O: [' ██████╗ ', '██╔═══██╗', '██║   ██║', '██║   ██║', '╚██████╔╝', ' ╚═════╝ '],
  Y: ['██╗   ██╗', '╚██╗ ██╔╝', ' ╚████╔╝ ', '  ╚██╔╝  ', '   ██║   ', '   ╚═╝   '],
};

const WORD = 'DEPLOY';

/** Build the 6 wordmark rows by joining each letter's glyph block column-wise. */
function buildWordmark(): string[] {
  const rows = ['', '', '', '', '', ''];
  for (const ch of WORD) {
    const g = GLYPHS[ch]!;
    const width = Math.max(...g.map((r) => r.length));
    for (let i = 0; i < 6; i++) rows[i] += g[i]!.padEnd(width, ' ') + ' ';
  }
  return rows.map((r) => r.replace(/\s+$/, ''));
}

const WORDMARK = buildWordmark();
const WORDMARK_WIDTH = Math.max(...WORDMARK.map((l) => l.length));

// cyan → teal → green: evokes "scan / secure / go".
const PALETTE = ['#36d1dc', '#2cc0c8', '#23afb3', '#2a9d8f', '#43aa8b', '#52b788'];

// Right-aligned "READY" accent under the DEPLOY wordmark.
const READY_ACCENT = '▸ R E A D Y ◂'.padStart(WORDMARK_WIDTH);

const TAGLINE = 'Production-readiness scanner · find issues before you deploy';

/** Build a compact boxed logo for narrow terminals (no emoji → always aligns). */
function buildCompact(): string[] {
  const label = 'D E P L O Y  ▸  R E A D Y';
  const inner = label.length + 6;
  const pad = inner - label.length;
  const left = Math.floor(pad / 2);
  const mid = ' '.repeat(left) + label + ' '.repeat(pad - left);
  return ['╔' + '═'.repeat(inner) + '╗', '║' + mid + '║', '╚' + '═'.repeat(inner) + '╝'];
}

const COMPACT = buildCompact();

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export class Banner {
  static async play(version: string): Promise<void> {
    const tty = Boolean(process.stdout.isTTY);
    const cols = process.stdout.columns ?? 80;
    const wide = cols >= 64;

    console.log('');
    if (!tty) {
      const art = wide ? WORDMARK : COMPACT;
      art.forEach((l, i) => console.log('  ' + colorLine(l, i)));
      if (wide) console.log('  ' + chalk.hex('#52b788').bold(READY_ACCENT));
      Banner.subtitle(version);
      return;
    }

    if (wide) {
      for (let i = 0; i < WORDMARK.length; i++) {
        console.log('  ' + colorLine(WORDMARK[i]!, i));
        await sleep(55);
      }
      console.log('  ' + chalk.hex('#52b788').bold(READY_ACCENT));
      await sleep(60);
    } else {
      for (let i = 0; i < COMPACT.length; i++) {
        console.log('  ' + chalk.hex(PALETTE[i % PALETTE.length]!)(COMPACT[i]!));
        await sleep(70);
      }
    }
    await sleep(80);
    await Banner.typeTagline();
    Banner.subtitle(version);
  }

  private static async typeTagline(): Promise<void> {
    process.stdout.write('  ');
    for (const ch of TAGLINE) {
      process.stdout.write(chalk.gray(ch));
      await sleep(8);
    }
    process.stdout.write('\n');
  }

  private static subtitle(version: string): void {
    if (!process.stdout.isTTY) console.log(chalk.gray('  ' + TAGLINE));
    console.log(chalk.gray(`  v${version} · local-first · AI-optional · your code never leaves unless you say so`));
    console.log(chalk.gray(`  type ${chalk.cyan('help')} for all commands, or ${chalk.cyan('menu')} for the guided flow`));
    console.log('');
  }
}

function colorLine(line: string, i: number): string {
  return chalk.hex(PALETTE[i % PALETTE.length]!)(line);
}
