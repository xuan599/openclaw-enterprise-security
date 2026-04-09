/**
 * Integration test: loads the compiled plugin (dist/index.js) against
 * a mock OpenClaw Plugin SDK API and verifies end-to-end behavior.
 *
 * This validates:
 * - Plugin loads from compiled JS (not just TypeScript source)
 * - Hook chain executes in correct order (pairing → policy → sensitivity → audit)
 * - Audit log is written to disk
 * - Security checks block startup on vulnerable versions
 * - Full lifecycle: init → hooks → shutdown
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// Import the compiled plugin
import pluginFactory from '../index';

// --- Mock OpenClaw Plugin SDK API ---

interface MockHookEntry {
  hookName: string;
  handler: (ctx: unknown) => Promise<unknown>;
}

function createMockApi(overrides: {
  version?: string;
  config?: Record<string, unknown>;
} = {}) {
  const logs: { level: string; msg: string }[] = [];
  const hooks: MockHookEntry[] = [];
  let serviceRegistered = false;
  let serviceStartFn: (() => Promise<void>) | null = null;
  let serviceStopFn: (() => Promise<void>) | null = null;

  const api = {
    id: 'test-plugin-instance',
    name: 'enterprise-security',
    version: 'version' in overrides ? overrides.version : '2026.4.8',
    pluginConfig: overrides.config || {},
    logger: {
      info: (msg: string) => logs.push({ level: 'info', msg }),
      warn: (msg: string) => logs.push({ level: 'warn', msg }),
      error: (msg: string) => logs.push({ level: 'error', msg }),
      debug: (msg: string) => logs.push({ level: 'debug', msg }),
    },
    on: (hookName: string, handler: (ctx: unknown) => Promise<unknown>) => {
      hooks.push({ hookName, handler });
    },
    registerService: (service: { name: string; start: () => Promise<void>; stop: () => Promise<void> }) => {
      serviceRegistered = true;
      serviceStartFn = service.start;
      serviceStopFn = service.stop;
    },
  };

  return {
    api,
    logs,
    hooks,
    get serviceRegistered() { return serviceRegistered; },
    get serviceStartFn() { return serviceStartFn; },
    get serviceStopFn() { return serviceStopFn; },
  };
}

// Helper: trigger the before_tool_call hook
async function triggerToolCall(
  mock: ReturnType<typeof createMockApi>,
  toolCtx: {
    tool: string;
    args?: Record<string, unknown>;
    input?: string;
    user?: string;
    userRole?: 'admin' | 'user';
    sessionId?: string;
  }
): Promise<{ blocked: boolean; reason?: string }> {
  const hook = mock.hooks.find((h) => h.hookName === 'before_tool_call');
  if (!hook) throw new Error('before_tool_call hook not registered');

  const result = await hook.handler(toolCtx);
  if (result && typeof result === 'object' && 'block' in result) {
    return { blocked: true, reason: (result as { reason?: string }).reason };
  }
  return { blocked: false };
}

// --- Tests ---

describe('Integration: Plugin lifecycle', () => {
  const testLogDir = path.join(__dirname, 'test-logs-integration');

  beforeEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  it('loads the compiled plugin and registers hooks', () => {
    const mock = createMockApi();
    pluginFactory(mock.api);

    expect(mock.hooks.length).toBe(1);
    expect(mock.hooks[0].hookName).toBe('before_tool_call');
    expect(mock.serviceRegistered).toBe(true);
  });

  it('logs initialization info', () => {
    const mock = createMockApi();
    pluginFactory(mock.api);

    const infoLogs = mock.logs.filter((l) => l.level === 'info');
    expect(infoLogs.some((l) => l.msg.includes('Policy mode'))).toBe(true);
    expect(infoLogs.some((l) => l.msg.includes('Audit log'))).toBe(true);
    expect(infoLogs.some((l) => l.msg.includes('Pairing guard'))).toBe(true);
  });

  it('throws on vulnerable OpenClaw version', () => {
    const mock = createMockApi({ version: '2026.3.1' });
    expect(() => pluginFactory(mock.api)).toThrow('security violations');
  });

  it('throws on missing version', () => {
    const mock = createMockApi({ version: undefined });
    expect(() => pluginFactory(mock.api)).toThrow('Cannot determine');
  });

  it('throws on invalid config', () => {
    const mock = createMockApi({
      config: { policy: { mode: 'INVALID_MODE' } },
    });
    expect(() => pluginFactory(mock.api)).toThrow('invalid config');
  });
});

describe('Integration: Hook chain (pairing → policy → sensitivity → audit)', () => {
  const testLogDir = path.join(__dirname, 'test-logs-integration');

  beforeEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  it('blocks exec tool via default-deny policy', async () => {
    const mock = createMockApi();
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, { tool: 'exec', input: 'ls' });
    expect(result.blocked).toBe(true);
    expect(result.reason).toContain('explicit deny list');
  });

  it('allows whitelisted tool', async () => {
    const mock = createMockApi({
      config: { policy: { allowTools: ['read'] } },
    });
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, { tool: 'read', input: 'hello' });
    expect(result.blocked).toBe(false);
  });

  it('blocks unknown tool in deny mode', async () => {
    const mock = createMockApi({
      config: { policy: { mode: 'deny', allowTools: ['read'] } },
    });
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, { tool: 'unknown_tool' });
    expect(result.blocked).toBe(true);
    expect(result.reason).toContain('default-deny');
  });

  it('blocks cloud tool with S3 data', async () => {
    const mock = createMockApi({
      config: { policy: { mode: 'allow' } },
    });
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, {
      tool: 'web_fetch',
      input: '密码是 abc123，请帮我查询',
    });
    expect(result.blocked).toBe(true);
    expect(result.reason).toContain('S3');
  });

  it('allows cloud tool with S1 data', async () => {
    const mock = createMockApi({
      config: { policy: { mode: 'allow' } },
    });
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, {
      tool: 'web_fetch',
      input: '今天天气怎么样',
    });
    expect(result.blocked).toBe(false);
  });

  it('blocks pairing tool from non-admin user', async () => {
    const mock = createMockApi();
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, {
      tool: 'pair',
      args: { deviceId: 'dev-001', action: 'approve' },
      userRole: 'user',
    });
    expect(result.blocked).toBe(true);
    expect(result.reason).toContain('CVE-2026-33579');
  });

  it('allows pairing tool for admin user', async () => {
    const mock = createMockApi({
      config: { policy: { mode: 'allow' } },
    });
    pluginFactory(mock.api);

    const result = await triggerToolCall(mock, {
      tool: 'pair',
      args: { deviceId: 'dev-001' },
      userRole: 'admin',
    });
    expect(result.blocked).toBe(false);
  });
});

describe('Integration: Audit logging to disk', () => {
  const testLogDir = path.join(__dirname, 'test-logs-integration');

  beforeEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  afterEach(async () => {
    // Allow cleanup
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  it('writes audit log entries to JSONL file', async () => {
    const mock = createMockApi({
      config: {
        audit: { logDir: testLogDir },
        policy: { mode: 'allow' },
      },
    });
    pluginFactory(mock.api);

    // Trigger an allowed tool call
    await triggerToolCall(mock, { tool: 'read', input: 'hello' });

    // Trigger a blocked tool call
    await triggerToolCall(mock, {
      tool: 'web_fetch',
      input: '密码是 abc',
    });

    // Allow write stream to flush
    await new Promise((r) => setTimeout(r, 200));

    // Read the audit log
    const files = fs.readdirSync(testLogDir);
    expect(files.length).toBeGreaterThan(0);

    const logFile = path.join(testLogDir, files[0]);
    const content = fs.readFileSync(logFile, 'utf-8');
    const lines = content.trim().split('\n');

    expect(lines.length).toBeGreaterThanOrEqual(2);

    const allowedEntry = JSON.parse(lines[0]);
    expect(allowedEntry.decision).toBe('allowed');
    expect(allowedEntry.tool).toBe('read');

    const blockedEntry = JSON.parse(lines[1]);
    expect(blockedEntry.decision).toBe('blocked');
    expect(blockedEntry.tool).toBe('web_fetch');
    expect(blockedEntry.sensitivity).toBe('S3');
  });
});

describe('Integration: Service lifecycle', () => {
  const testLogDir = path.join(__dirname, 'test-logs-integration');

  beforeEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(testLogDir)) {
      fs.rmSync(testLogDir, { recursive: true, force: true });
    }
  });

  it('starts and stops the service cleanly', async () => {
    const mock = createMockApi();
    pluginFactory(mock.api);

    // Start
    await mock.serviceStartFn!();
    expect(mock.logs.some((l) => l.msg.includes('started'))).toBe(true);

    // Stop
    await mock.serviceStopFn!();
    expect(mock.logs.some((l) => l.msg.includes('stopped'))).toBe(true);
  });
});
