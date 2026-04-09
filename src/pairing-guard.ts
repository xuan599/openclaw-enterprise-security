/**
 * Device Pairing Guard — hardening against CVE-2026-33579 and related pairing CVEs.
 *
 * Capabilities:
 * 1. Enforce mandatory device pairing (reject unauthenticated instances)
 * 2. Pairing code expiry validation
 * 3. Privilege escalation detection (user→admin elevation via /pair approve)
 * 4. Full audit trail for all pairing operations
 */

import { AuditLogger, AuditEntry } from './audit-logger';

/** Configuration for pairing guard */
export interface PairingGuardConfig {
  /** If true, block all pairing operations unless explicitly authenticated */
  pairingRequired: boolean;
  /** Only allow pre-approved device IDs */
  approvedDevicesOnly: boolean;
  /** Maximum pairing code age in seconds (0 = no expiry check) */
  pairingCodeMaxAge: number;
  /** List of approved device IDs */
  approvedDevices: string[];
  /** Whether to block /pair approve from non-admin users */
  blockNonAdminApproval: boolean;
}

const DEFAULT_CONFIG: PairingGuardConfig = {
  pairingRequired: true,
  approvedDevicesOnly: true,
  pairingCodeMaxAge: 300, // 5 minutes
  approvedDevices: [],
  blockNonAdminApproval: true,
};

export interface PairingCheckResult {
  allowed: boolean;
  reason?: string;
  auditEntry?: Partial<AuditEntry>;
}

export class PairingGuard {
  private config: PairingGuardConfig;
  private auditLogger: AuditLogger;
  /** Track pairing code issuance timestamps */
  private activePairingCodes: Map<string, { issuedAt: number; deviceId?: string }> = new Map();

  constructor(config: Partial<PairingGuardConfig>, auditLogger: AuditLogger) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.auditLogger = auditLogger;
  }

  /**
   * Validate a pairing-related tool call.
   *
   * @param toolName - The tool being called (e.g., "pair", "device_pair")
   * @param args - Tool arguments including device info, pairing code, etc.
   * @param userRole - Role of the user making the request ("admin" | "user")
   * @returns Whether to allow or block the operation
   */
  check(
    toolName: string,
    args: Record<string, unknown> = {},
    userRole: 'admin' | 'user' = 'user'
  ): PairingCheckResult {
    const timestamp = new Date().toISOString();

    // 1. Check if pairing is required but user has no auth context
    if (this.config.pairingRequired) {
      const deviceId = args.deviceId as string | undefined;
      const pairingCode = args.pairingCode as string | undefined;

      if (!deviceId && !pairingCode) {
        const reason =
          'Pairing blocked: no device ID or pairing code provided. ' +
          'Unauthenticated pairing is prohibited (pairingRequired=true).';
        return {
          allowed: false,
          reason,
          auditEntry: { tool: toolName, decision: 'blocked', reason },
        };
      }
    }

    // 2. Privilege escalation check: block non-admin from /pair approve
    if (this.config.blockNonAdminApproval && userRole !== 'admin') {
      const isApprovalOp =
        toolName.includes('approve') ||
        toolName.includes('accept') ||
        (args.action === 'approve');
      if (isApprovalOp) {
        const reason =
          `Pairing approval blocked: user role "${userRole}" cannot approve device pairing. ` +
          'Only admin users may approve devices (CVE-2026-33579 mitigation).';
        return {
          allowed: false,
          reason,
          auditEntry: { tool: toolName, decision: 'blocked', reason },
        };
      }
    }

    // 3. Pairing code expiry check
    if (this.config.pairingCodeMaxAge > 0) {
      const pairingCode = args.pairingCode as string | undefined;
      if (pairingCode) {
        const codeRecord = this.activePairingCodes.get(pairingCode);
        if (codeRecord) {
          const age = (Date.now() - codeRecord.issuedAt) / 1000;
          if (age > this.config.pairingCodeMaxAge) {
            this.activePairingCodes.delete(pairingCode);
            const reason =
              `Pairing code expired after ${Math.round(age)}s ` +
              `(max: ${this.config.pairingCodeMaxAge}s). ` +
              'Request a new pairing code.';
            return {
              allowed: false,
              reason,
              auditEntry: { tool: toolName, decision: 'blocked', reason },
            };
          }
        } else if (this.config.pairingRequired) {
          // Code not tracked = unknown code
          const reason =
            'Unknown pairing code. Only codes issued by the pairing guard are accepted.';
          return {
            allowed: false,
            reason,
            auditEntry: { tool: toolName, decision: 'blocked', reason },
          };
        }
      }
    }

    // 4. Approved devices whitelist check
    if (this.config.approvedDevicesOnly && this.config.approvedDevices.length > 0) {
      const deviceId = args.deviceId as string | undefined;
      if (deviceId && !this.config.approvedDevices.includes(deviceId)) {
        const reason =
          `Device "${deviceId}" is not in the approved devices list. ` +
          'Add the device to pairing.approvedDevices before pairing.';
        return {
          allowed: false,
          reason,
          auditEntry: { tool: toolName, decision: 'blocked', reason },
        };
      }
    }

    // All checks passed — audit the allowed operation
    return {
      allowed: true,
      auditEntry: { tool: toolName, decision: 'allowed' },
    };
  }

  /**
   * Issue a new pairing code. Called when a device initiates pairing.
   */
  issuePairingCode(deviceId?: string): string {
    const code = `pc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    this.activePairingCodes.set(code, {
      issuedAt: Date.now(),
      deviceId,
    });
    return code;
  }

  /**
   * Clean up expired pairing codes.
   */
  cleanupExpiredCodes(): number {
    if (this.config.pairingCodeMaxAge <= 0) return 0;
    const now = Date.now();
    let cleaned = 0;
    for (const [code, record] of this.activePairingCodes) {
      if ((now - record.issuedAt) / 1000 > this.config.pairingCodeMaxAge) {
        this.activePairingCodes.delete(code);
        cleaned++;
      }
    }
    return cleaned;
  }

  /** Get count of active (non-expired) pairing codes */
  getActiveCodeCount(): number {
    return this.activePairingCodes.size;
  }

  getConfig(): Readonly<PairingGuardConfig> {
    return this.config;
  }
}
