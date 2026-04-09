import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../policy-engine';

describe('PolicyEngine', () => {
  it('blocks tools not in allow list when mode is deny', () => {
    const engine = new PolicyEngine({ mode: 'deny', allowTools: ['read'], denyTools: [], allowPatterns: [] });
    expect(engine.check('read')).toBeUndefined();
    expect(engine.check('write')).toEqual({ block: true, reason: expect.stringContaining('not in the allow list') });
  });

  it('always blocks tools in explicit deny list', () => {
    const engine = new PolicyEngine({
      mode: 'allow',
      allowTools: ['exec'],
      denyTools: ['exec'],
      allowPatterns: [],
    });
    // denyTools takes precedence over allowTools
    expect(engine.check('exec')).toEqual({ block: true, reason: expect.stringContaining('explicit deny list') });
  });

  it('blocks default dangerous tools', () => {
    const engine = new PolicyEngine();
    expect(engine.check('exec')).toEqual({ block: true, reason: expect.any(String) });
    expect(engine.check('full')).toEqual({ block: true, reason: expect.any(String) });
    expect(engine.check('shell')).toEqual({ block: true, reason: expect.any(String) });
    expect(engine.check('bash')).toEqual({ block: true, reason: expect.any(String) });
  });

  it('allows tools matching glob patterns', () => {
    const engine = new PolicyEngine({
      mode: 'deny',
      allowTools: [],
      denyTools: [],
      allowPatterns: ['file_*', 'read*'],
    });
    expect(engine.check('file_read')).toBeUndefined();
    expect(engine.check('file_write')).toBeUndefined();
    expect(engine.check('read')).toBeUndefined();
    expect(engine.check('read_config')).toBeUndefined();
    expect(engine.check('write_config')).toEqual({ block: true, reason: expect.any(String) });
  });

  it('allows all non-denied tools when mode is allow', () => {
    const engine = new PolicyEngine({ mode: 'allow', allowTools: [], denyTools: ['exec'], allowPatterns: [] });
    expect(engine.check('read')).toBeUndefined();
    expect(engine.check('write')).toBeUndefined();
    expect(engine.check('exec')).toEqual({ block: true, reason: expect.any(String) });
  });

  it('reloads config at runtime', () => {
    const engine = new PolicyEngine({ mode: 'deny', allowTools: [], denyTools: [], allowPatterns: [] });
    expect(engine.check('read')).toEqual({ block: true, reason: expect.any(String) });
    engine.reload({ allowTools: ['read'] });
    expect(engine.check('read')).toBeUndefined();
  });
});
