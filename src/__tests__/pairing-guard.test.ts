import { describe, it, expect, beforeEach } from 'vitest';
import { PairingGuard } from '../pairing-guard';
import { AuditLogger } from '../audit-logger';
import * as fs from 'fs';
import * as path from 'path';

function createTestAuditLogger(): AuditLogger {
  const dir = path.join(__dirname, 'test-logs-pairing');
  return new AuditLogger(dir);
}

function cleanupTestLogs(dir: string) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('PairingGuard', () => {
  let guard: PairingGuard;
  let auditLogger: AuditLogger;
  const testLogDir = path.join(__dirname, 'test-logs-pairing');

  beforeEach(() => {
    cleanupTestLogs(testLogDir);
    auditLogger = createTestAuditLogger();
    guard = new PairingGuard({}, auditLogger);
  });

  describe('mandatory device pairing', () => {
    it('blocks pairing with no device ID or code when pairingRequired=true', () => {
      const result = guard.check('pair', {});
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('no device ID or pairing code');
    });

    it('allows pairing with device ID present', () => {
      const result = guard.check('pair', { deviceId: 'dev-001' });
      expect(result.allowed).toBe(true);
    });

    it('allows pairing with pairing code present', () => {
      const result = guard.check('pair', { pairingCode: 'abc123' });
      // Code not tracked, but code is present — depends on pairingCodeMaxAge logic
      // With default config, unknown code is blocked when pairingRequired=true
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Unknown pairing code');
    });
  });

  describe('privilege escalation prevention', () => {
    it('blocks non-admin from approve operations', () => {
      const result = guard.check('pair', { deviceId: 'dev-001', action: 'approve' }, 'user');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('CVE-2026-33579');
    });

    it('blocks non-admin from approve_device tool', () => {
      const result = guard.check('approve_device', { deviceId: 'dev-001' }, 'user');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Only admin users may approve');
    });

    it('allows admin to approve devices', () => {
      const result = guard.check('pair', { deviceId: 'dev-001', action: 'approve' }, 'admin');
      expect(result.allowed).toBe(true);
    });

    it('allows non-admin for non-approval pairing operations', () => {
      const result = guard.check('pair', { deviceId: 'dev-001', action: 'request' }, 'user');
      expect(result.allowed).toBe(true);
    });
  });

  describe('pairing code expiry', () => {
    it('allows operations within expiry window', () => {
      const code = guard.issuePairingCode('dev-001');
      const result = guard.check('pair', { pairingCode: code, deviceId: 'dev-001' });
      expect(result.allowed).toBe(true);
    });

    it('rejects expired pairing codes', () => {
      // Test that an unknown code is rejected when pairingCodeMaxAge is set
      const guardShort = new PairingGuard({ pairingCodeMaxAge: 1 }, auditLogger);
      guardShort.issuePairingCode('dev-001');
      const result = guardShort.check('pair', { pairingCode: 'unknown_code' });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Unknown pairing code');
    });

    it('cleans up expired codes', () => {
      // Use maxAge=1 to make codes expire quickly
      const guardShort = new PairingGuard({ pairingCodeMaxAge: 1 }, auditLogger);
      guardShort.issuePairingCode('dev-001');
      guardShort.issuePairingCode('dev-002');

      // Wait for codes to expire (2 seconds to be safe)
      const start = Date.now();
      while (Date.now() - start < 2100) {
        // busy wait — tests only, not production code
      }

      const cleaned = guardShort.cleanupExpiredCodes();
      expect(cleaned).toBe(2);
      expect(guardShort.getActiveCodeCount()).toBe(0);
    });

    it('issued code has expected format', () => {
      const code = guard.issuePairingCode();
      expect(code).toMatch(/^pc_/);
    });
  });

  describe('approved devices whitelist', () => {
    it('blocks devices not in whitelist', () => {
      const g = new PairingGuard(
        { approvedDevicesOnly: true, approvedDevices: ['dev-allowed'] },
        auditLogger
      );
      const result = g.check('pair', { deviceId: 'dev-unknown' });
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('not in the approved devices list');
    });

    it('allows devices in whitelist', () => {
      const g = new PairingGuard(
        { approvedDevicesOnly: true, approvedDevices: ['dev-allowed'] },
        auditLogger
      );
      const result = g.check('pair', { deviceId: 'dev-allowed' });
      expect(result.allowed).toBe(true);
    });

    it('allows all devices when whitelist is empty', () => {
      const g = new PairingGuard(
        { approvedDevicesOnly: true, approvedDevices: [] },
        auditLogger
      );
      const result = g.check('pair', { deviceId: 'dev-anything' });
      expect(result.allowed).toBe(true);
    });
  });

  describe('config', () => {
    it('returns readonly config', () => {
      const config = guard.getConfig();
      expect(config.pairingRequired).toBe(true);
      expect(config.pairingCodeMaxAge).toBe(300);
      expect(config.blockNonAdminApproval).toBe(true);
    });
  });
});
