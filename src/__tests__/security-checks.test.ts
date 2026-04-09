import { describe, it, expect } from 'vitest';
import {
  checkCoreVersion,
  checkPairingSecurity,
  runStartupChecks,
} from '../security-checks';

describe('SecurityChecks', () => {
  describe('checkCoreVersion', () => {
    it('blocks undefined version', () => {
      const result = checkCoreVersion(undefined);
      expect(result.passed).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('Cannot determine');
    });

    it('blocks version below 2026.3.28', () => {
      const result = checkCoreVersion('2026.3.22');
      expect(result.passed).toBe(false);
      expect(result.errors[0]).toContain('CVE-2026-33579');
    });

    it('blocks very old version', () => {
      const result = checkCoreVersion('2025.12.1');
      expect(result.passed).toBe(false);
    });

    it('passes version exactly 2026.3.28', () => {
      const result = checkCoreVersion('2026.3.28');
      expect(result.passed).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('passes version above 2026.3.28', () => {
      const result = checkCoreVersion('2026.4.8');
      expect(result.passed).toBe(true);
    });

    it('passes version with patch suffix', () => {
      const result = checkCoreVersion('2026.3.28.1');
      expect(result.passed).toBe(true);
    });
  });

  describe('checkPairingSecurity', () => {
    it('blocks allowInsecureAuth=true', () => {
      const result = checkPairingSecurity({ allowInsecureAuth: true });
      expect(result.passed).toBe(false);
      expect(result.errors[0]).toContain('CVE-2026-32034');
    });

    it('passes with empty config', () => {
      const result = checkPairingSecurity({});
      expect(result.passed).toBe(true);
    });

    it('passes with allowInsecureAuth=false', () => {
      const result = checkPairingSecurity({ allowInsecureAuth: false });
      expect(result.passed).toBe(true);
    });

    it('warns when pairingRequired=false', () => {
      const result = checkPairingSecurity({ pairingRequired: false });
      expect(result.passed).toBe(true);
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0]).toContain('6 CVEs');
    });

    it('warns when approvedDevicesOnly=false', () => {
      const result = checkPairingSecurity({ approvedDevicesOnly: false });
      expect(result.warnings).toHaveLength(1);
    });
  });

  describe('runStartupChecks', () => {
    it('passes with safe version and secure config', () => {
      const result = runStartupChecks({
        coreVersion: '2026.4.8',
        pairingConfig: { allowInsecureAuth: false },
      });
      expect(result.passed).toBe(true);
    });

    it('fails with old version even if pairing is secure', () => {
      const result = runStartupChecks({
        coreVersion: '2026.3.1',
        pairingConfig: { allowInsecureAuth: false },
      });
      expect(result.passed).toBe(false);
    });

    it('fails with safe version but insecure pairing', () => {
      const result = runStartupChecks({
        coreVersion: '2026.4.8',
        pairingConfig: { allowInsecureAuth: true },
      });
      expect(result.passed).toBe(false);
    });

    it('accumulates errors from both checks', () => {
      const result = runStartupChecks({
        coreVersion: '2026.1.1',
        pairingConfig: { allowInsecureAuth: true },
      });
      expect(result.passed).toBe(false);
      expect(result.errors.length).toBeGreaterThanOrEqual(2);
    });
  });
});
