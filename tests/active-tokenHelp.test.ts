import { jwtRetrievalSteps, renderTokenHelp } from '../src/active/tokenHelp';

describe('active/tokenHelp', () => {
  it('gives concrete numbered steps to obtain a JWT', () => {
    const steps = jwtRetrievalSteps();
    expect(steps.length).toBeGreaterThanOrEqual(4);
    const all = steps.join('\n').toLowerCase();
    expect(all).toContain('log in'); // log into the app
    expect(all).toContain('network'); // devtools network tab
    expect(all).toContain('authorization'); // the Authorization: Bearer header
  });

  it('renders help that mentions --token and the expiry caveat', () => {
    const help = renderTokenHelp().toLowerCase();
    expect(help).toContain('--token');
    expect(help).toContain('expire'); // remind tokens expire
  });
});
