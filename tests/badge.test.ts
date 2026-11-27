import { badgeColor, badgeMarkdown, badgeSvg, badgeUrl, normalizeScore } from '../src/ui/badge';

describe('badge', () => {
  it('maps score bands to colors', () => {
    expect(badgeColor(100)).toBe('brightgreen');
    expect(badgeColor(90)).toBe('brightgreen');
    expect(badgeColor(89)).toBe('green');
    expect(badgeColor(75)).toBe('green');
    expect(badgeColor(74)).toBe('yellow');
    expect(badgeColor(60)).toBe('yellow');
    expect(badgeColor(59)).toBe('orange');
    expect(badgeColor(40)).toBe('orange');
    expect(badgeColor(39)).toBe('red');
    expect(badgeColor(0)).toBe('red');
  });

  it('clamps and rounds scores', () => {
    expect(normalizeScore(150)).toBe(100);
    expect(normalizeScore(-5)).toBe(0);
    expect(normalizeScore(86.6)).toBe(87);
    expect(normalizeScore(NaN)).toBe(0);
  });

  it('builds a shields.io static badge markdown', () => {
    expect(badgeUrl(87)).toBe('https://img.shields.io/badge/DeployReady-87%2F100-green');
    expect(badgeMarkdown(95)).toBe(
      '![DeployReady score](https://img.shields.io/badge/DeployReady-95%2F100-brightgreen)',
    );
  });

  it('renders a local SVG with the score and no external references', () => {
    const svg = badgeSvg(39);
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain('39/100');
    expect(svg).toContain('#e05d44');
    expect(svg).not.toMatch(/https?:\/\/(?!www\.w3\.org)/);
  });
});
