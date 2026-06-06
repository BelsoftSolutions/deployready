/**
 * Animated welcome banner. ASCII wordmark with a line-by-line gradient reveal.
 *
 * Degrades gracefully:
 * - No TTY (piped/CI): prints a plain banner instantly, no delays.
 * - Narrow terminals (< 84 cols): uses a compact boxed logo instead of the
 *   wide block letters so it never wraps into garbage.
 */
import chalk from 'chalk';

const WORDMARK = [
  '███████╗███╗   ██╗████████╗███████╗██████╗ ██████╗ ██╗███████╗███████╗',
  '██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║██╔════╝██╔════╝',
  '█████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝██████╔╝██║███████╗█████╗  ',
  '██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔═══╝ ██║╚════██║██╔══╝  ',
  '███████╗██║ ╚████║   ██║   ███████╗██║  ██║██║     ██║███████║███████╗',
  '╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝',
];

// cyan → teal → green: evokes "scan / secure / go".
const PALETTE = ['#36d1dc', '#2cc0c8', '#23afb3', '#2a9d8f', '#43aa8b', '#52b788'];

// Accent under the "ENTERPRISE" wordmark so the full brand reads "EnterpriseReady".
const READY_ACCENT = '                                              ▸ R E A D Y ◂';

const COMPACT = [
  '╔══════════════════════════════════════════╗',
  '║   ⚡  E N T E R P R I S E   R E A D Y      ║',
  '╚══════════════════════════════════════════╝',
];

const TAGLINE = 'Production-readiness scanner · find issues before you deploy';

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export class Banner {
  static async play(version: string): Promise<void> {
    const tty = Boolean(process.stdout.isTTY);
    const cols = process.stdout.columns ?? 80;
    const wide = cols >= 84;

    console.log('');
    if (!tty) {
      // Non-interactive: instant, no animation.
      const art = wide ? WORDMARK : COMPACT;
      art.forEach((l, i) => console.log('  ' + colorLine(l, i)));
      if (wide) console.log(chalk.hex('#52b788').bold(READY_ACCENT));
      Banner.subtitle(version);
      return;
    }

    if (wide) {
      for (let i = 0; i < WORDMARK.length; i++) {
        console.log('  ' + colorLine(WORDMARK[i]!, i));
        await sleep(55);
      }
      console.log(chalk.hex('#52b788').bold(READY_ACCENT));
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
    console.log('');
  }
}

function colorLine(line: string, i: number): string {
  return chalk.hex(PALETTE[i % PALETTE.length]!)(line);
}
