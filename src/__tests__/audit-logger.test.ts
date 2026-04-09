import { describe, it, expect, afterEach } from 'vitest';
import { AuditLogger } from '../audit-logger';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('AuditLogger', () => {
  let tmpDir: string;

  afterEach(async () => {
    if (tmpDir) {
      await fs.promises.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('creates log directory and writes JSONL entries', async () => {
    tmpDir = path.join(os.tmpdir(), `audit-test-${Date.now()}`);
    const logger = new AuditLogger(tmpDir);

    logger.log({
      ts: '2026-04-08T12:00:00.000Z',
      tool: 'read',
      decision: 'allowed',
      user: 'test-user',
    });

    logger.log({
      ts: '2026-04-08T12:00:01.000Z',
      tool: 'exec',
      decision: 'blocked',
      reason: 'Tool "exec" is in the explicit deny list',
      sensitivity: 'S3',
    });

    await logger.close();

    // Read back and verify
    const content = await fs.promises.readFile(logger.getLogPath(), 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);

    const entry1 = JSON.parse(lines[0]);
    expect(entry1.tool).toBe('read');
    expect(entry1.decision).toBe('allowed');

    const entry2 = JSON.parse(lines[1]);
    expect(entry2.tool).toBe('exec');
    expect(entry2.decision).toBe('blocked');
    expect(entry2.sensitivity).toBe('S3');
  });

  it('appends to existing log file', async () => {
    tmpDir = path.join(os.tmpdir(), `audit-test-${Date.now()}`);
    const logger1 = new AuditLogger(tmpDir);
    logger1.log({ ts: new Date().toISOString(), tool: 'read', decision: 'allowed' });
    await logger1.close();

    const logger2 = new AuditLogger(tmpDir);
    logger2.log({ ts: new Date().toISOString(), tool: 'write', decision: 'allowed' });
    await logger2.close();

    const content = await fs.promises.readFile(logger2.getLogPath(), 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);
  });
});
