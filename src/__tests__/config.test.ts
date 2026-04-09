import { describe, it, expect } from 'vitest';
import { validateConfig, safeValidateConfig, PluginConfigSchema } from '../config';

describe('Config validation (zod)', () => {
  it('applies defaults for empty input', () => {
    const config = validateConfig({});
    expect(config.policy.mode).toBe('deny');
    expect(config.policy.denyTools).toEqual(['exec', 'full', 'shell', 'bash']);
    expect(config.policy.allowTools).toEqual([]);
    expect(config.audit.logDir).toBe('./logs');
    expect(config.sensitivity.scanArguments).toBe(true);
  });

  it('validates a full config', () => {
    const config = validateConfig({
      policy: {
        mode: 'deny',
        allowTools: ['read', 'write'],
        denyTools: ['exec'],
        allowPatterns: ['mcp__*'],
      },
      audit: { logDir: '/var/log/audit' },
      sensitivity: {
        s3Patterns: ['密码', /secret/i],
        scanArguments: false,
      },
      pairing: {
        allowInsecureAuth: false,
        pairingRequired: true,
      },
    });
    expect(config.policy.allowTools).toEqual(['read', 'write']);
    expect(config.policy.allowPatterns).toEqual(['mcp__*']);
    expect(config.audit.logDir).toBe('/var/log/audit');
    expect(config.sensitivity.s3Patterns).toEqual(['密码', /secret/i]);
    expect(config.pairing.allowInsecureAuth).toBe(false);
  });

  it('rejects invalid mode', () => {
    const result = safeValidateConfig({
      policy: { mode: 'block_everything' },
    });
    expect(result.success).toBe(false);
    expect(result.errors!.some((e) => e.includes('mode'))).toBe(true);
  });

  it('rejects non-string tool names', () => {
    const result = safeValidateConfig({
      policy: { allowTools: [123] },
    });
    expect(result.success).toBe(false);
  });

  it('rejects non-boolean allowInsecureAuth', () => {
    const result = safeValidateConfig({
      pairing: { allowInsecureAuth: 'yes' },
    });
    expect(result.success).toBe(false);
    expect(result.errors!.some((e) => e.includes('allowInsecureAuth'))).toBe(true);
  });

  it('handles null input gracefully', () => {
    const result = safeValidateConfig(null);
    expect(result.success).toBe(false);
  });

  it('handles unexpected extra fields (strips them)', () => {
    const config = validateConfig({
      policy: { mode: 'deny' },
      unknownField: 'should be ignored',
    });
    expect(config.policy.mode).toBe('deny');
  });
});
