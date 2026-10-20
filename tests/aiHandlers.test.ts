import axios, { AxiosError, type AxiosResponse } from 'axios';
import { ClaudeHandler, describeHttpError } from '../src/ai/ClaudeHandler';
import { OpenAIHandler } from '../src/ai/OpenAIHandler';
import { OllamaHandler } from '../src/ai/OllamaHandler';

const FAKE_KEY = 'fake-test-key-not-real';
const PROMPT = { system: 'SYS', user: 'USR' };

function httpError(status: number): AxiosError {
  const response = { status, statusText: '', data: { secret: 'body-must-not-leak' }, headers: {}, config: {} } as AxiosResponse;
  return new AxiosError(`Request failed with status code ${status}`, 'ERR_BAD_RESPONSE', undefined, undefined, response);
}

let post: jest.SpyInstance;
beforeEach(() => {
  post = jest.spyOn(axios, 'post');
});
afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

describe('describeHttpError', () => {
  it.each([
    [401, 'authentication failed (check your API key)'],
    [403, 'authentication failed (check your API key)'],
    [429, 'rate limited (too many requests)'],
    [500, 'server returned 500'],
    [404, 'server returned 404'],
  ])('maps HTTP %i to a safe message without the response body', (status, msg) => {
    expect(describeHttpError(httpError(status))).toBe(msg);
  });

  it('reports timeouts', () => {
    const e = new AxiosError('timeout of 60000ms exceeded', 'ECONNABORTED');
    expect(describeHttpError(e)).toBe('request timed out');
  });

  it('falls back to the axios message for network errors with no response', () => {
    const e = new AxiosError('connect ECONNREFUSED', 'ECONNREFUSED');
    expect(describeHttpError(e)).toBe('connect ECONNREFUSED');
  });

  it('handles non-axios errors and non-error values', () => {
    expect(describeHttpError(new Error('boom'))).toBe('boom');
    expect(describeHttpError({})).toBe('unknown error');
  });
});

describe('ClaudeHandler', () => {
  it('sends the expected request (url, key header, body) and returns joined text blocks only', async () => {
    post.mockResolvedValue({
      data: { content: [{ type: 'text', text: 'one' }, { type: 'tool_use', id: 'x' }, { type: 'text', text: 'two' }] },
    });
    const out = await new ClaudeHandler(FAKE_KEY, 'test-model').complete(PROMPT);
    expect(out).toBe('one\ntwo');
    const [url, body, cfg] = post.mock.calls[0];
    expect(url).toBe('https://api.anthropic.com/v1/messages');
    expect(body).toEqual({
      model: 'test-model',
      max_tokens: 4096,
      system: 'SYS',
      messages: [{ role: 'user', content: 'USR' }],
    });
    expect(cfg.headers['x-api-key']).toBe(FAKE_KEY);
    expect(cfg.headers['anthropic-version']).toBe('2023-06-01');
    expect(cfg.timeout).toBe(60_000);
  });

  it('uses the default model when none is given', async () => {
    post.mockResolvedValue({ data: { content: [] } });
    await new ClaudeHandler(FAKE_KEY).complete(PROMPT);
    expect(post.mock.calls[0][1].model).toBe('claude-sonnet-4-6');
  });

  it.each([[{ data: {} }], [{ data: undefined }], [{ data: { content: [] } }]])(
    'returns an empty string for a response with no content (%j)',
    async (resp) => {
      post.mockResolvedValue(resp);
      expect(await new ClaudeHandler(FAKE_KEY).complete(PROMPT)).toBe('');
    },
  );

  it('wraps API failures in a sanitized error that never contains the key or response body', async () => {
    post.mockRejectedValue(httpError(401));
    const err = (await new ClaudeHandler(FAKE_KEY).complete(PROMPT).catch((e: Error) => e)) as Error;
    expect(err.message).toBe('Claude API request failed: authentication failed (check your API key)');
    expect(err.message).not.toContain(FAKE_KEY);
    expect(err.message).not.toContain('body-must-not-leak');
  });

  it('analyze() parses model JSON into unverified AI findings', async () => {
    const json = JSON.stringify({ summary: 'S', findings: [{ rule: 'r', title: 'T', severity: 'critical', category: 'config' }] });
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: `Here you go:\n${json}` }] } });
    const a = await new ClaudeHandler(FAKE_KEY).analyze(PROMPT);
    expect(a.summary).toBe('S');
    expect(a.findings).toHaveLength(1);
    expect(a.findings[0]).toMatchObject({ rule: 'r', source: 'ai', unverified: true, category: 'config' });
  });

  it('analyze() tolerates non-JSON model output instead of throwing', async () => {
    post.mockResolvedValue({ data: { content: [{ type: 'text', text: 'I cannot help with that.' }] } });
    const a = await new ClaudeHandler(FAKE_KEY).analyze(PROMPT);
    expect(a).toEqual({ summary: 'I cannot help with that.', findings: [] });
  });

  it('exposes a context-window budget', () => {
    expect(ClaudeHandler.contextTokens).toBe(100_000);
  });
});

describe('OpenAIHandler', () => {
  it('sends bearer auth and system+user messages, returns the first choice', async () => {
    post.mockResolvedValue({ data: { choices: [{ message: { content: 'hello' } }, { message: { content: 'ignored' } }] } });
    const out = await new OpenAIHandler(FAKE_KEY, 'test-model').complete(PROMPT);
    expect(out).toBe('hello');
    const [url, body, cfg] = post.mock.calls[0];
    expect(url).toBe('https://api.openai.com/v1/chat/completions');
    expect(body.model).toBe('test-model');
    expect(body.messages).toEqual([
      { role: 'system', content: 'SYS' },
      { role: 'user', content: 'USR' },
    ]);
    expect(body).not.toHaveProperty('response_format');
    expect(cfg.headers.Authorization).toBe(`Bearer ${FAKE_KEY}`);
  });

  it('requests JSON mode for analyze() but not for plain complete()', async () => {
    post.mockResolvedValue({ data: { choices: [{ message: { content: '{"summary":"x","findings":[]}' } }] } });
    const h = new OpenAIHandler(FAKE_KEY);
    await h.analyze(PROMPT);
    expect(post.mock.calls[0][1].response_format).toEqual({ type: 'json_object' });
    expect(post.mock.calls[0][1].model).toBe('gpt-4o-mini');
    await h.complete(PROMPT);
    expect(post.mock.calls[1][1]).not.toHaveProperty('response_format');
  });

  it.each([[{ data: {} }], [{ data: { choices: [] } }], [{ data: { choices: [{ message: {} }] } }]])(
    'returns an empty string when choices are missing/empty (%j)',
    async (resp) => {
      post.mockResolvedValue(resp);
      expect(await new OpenAIHandler(FAKE_KEY).complete(PROMPT)).toBe('');
    },
  );

  it('analyze() of an empty completion yields an empty analysis', async () => {
    post.mockResolvedValue({ data: { choices: [] } });
    expect(await new OpenAIHandler(FAKE_KEY).analyze(PROMPT)).toEqual({ summary: '', findings: [] });
  });

  it('wraps rate-limit errors without leaking the key', async () => {
    post.mockRejectedValue(httpError(429));
    const err = (await new OpenAIHandler(FAKE_KEY).complete(PROMPT).catch((e: Error) => e)) as Error;
    expect(err.message).toBe('OpenAI API request failed: rate limited (too many requests)');
    expect(err.message).not.toContain(FAKE_KEY);
  });
});

describe('OllamaHandler', () => {
  it('posts to the loopback chat endpoint on the configured port and returns message content', async () => {
    post.mockResolvedValue({ data: { message: { content: 'local answer' } } });
    const out = await new OllamaHandler(12345, 'tiny').complete(PROMPT);
    expect(out).toBe('local answer');
    const [url, body, cfg] = post.mock.calls[0];
    expect(url).toBe('http://127.0.0.1:12345/api/chat');
    expect(body).toEqual({
      model: 'tiny',
      stream: false,
      messages: [
        { role: 'system', content: 'SYS' },
        { role: 'user', content: 'USR' },
      ],
    });
    expect(cfg.timeout).toBe(120_000);
  });

  it('returns an empty string when the reply has no message', async () => {
    post.mockResolvedValue({ data: {} });
    expect(await new OllamaHandler(1, 'm').complete(PROMPT)).toBe('');
  });

  it('retries exactly once after a transient failure and then succeeds', async () => {
    jest.useFakeTimers();
    post.mockRejectedValueOnce(httpError(503)).mockResolvedValueOnce({ data: { message: { content: 'ok' } } });
    const p = new OllamaHandler(1, 'm').complete(PROMPT);
    await jest.advanceTimersByTimeAsync(1200);
    await expect(p).resolves.toBe('ok');
    expect(post).toHaveBeenCalledTimes(2);
  });

  it('gives up after two failures with a hint naming the port and model', async () => {
    jest.useFakeTimers();
    post.mockRejectedValue(new AxiosError('connect ECONNREFUSED', 'ECONNREFUSED'));
    const p = new OllamaHandler(4242, 'my-model').complete(PROMPT);
    const assertion = expect(p).rejects.toThrow(
      'Ollama request failed: connect ECONNREFUSED. Is Ollama running on port 4242 with model "my-model"?',
    );
    await jest.advanceTimersByTimeAsync(1200);
    await assertion;
    expect(post).toHaveBeenCalledTimes(2);
  });

  it('analyze() parses model output and has a smaller context budget than hosted models', async () => {
    post.mockResolvedValue({ data: { message: { content: '{"summary":"local","findings":[]}' } } });
    expect(await new OllamaHandler(1, 'm').analyze(PROMPT)).toEqual({ summary: 'local', findings: [] });
    expect(OllamaHandler.contextTokens).toBeLessThan(ClaudeHandler.contextTokens);
  });
});
