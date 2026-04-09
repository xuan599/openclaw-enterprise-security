/**
 * Runtime security checks for the Enterprise Security Plugin.
 *
 * Validates OpenClaw core version and security posture at plugin startup.
 * Blocks plugin activation on vulnerable configurations.
 */

/** Minimum OpenClaw version that fixes CVE-2026-33579 and related pairing CVEs */
const MIN_SAFE_VERSION = '2026.3.28';

/** Known CVEs addressed by MIN_SAFE_VERSION */
const PATCHED_CVES = [
  'CVE-2026-33579', // Privilege escalation in /pair approve (CVSS 8.1-9.8)
  'CVE-2026-32922', // Critical privilege escalation
  'CVE-2026-28472', // Critical auth bypass (before 2026.2.2)
  'CVE-2026-32001', // Auth bypass (before 2026.2.22)
  'CVE-2026-32057', // Auth bypass via Control UI client ID
  'CVE-2026-32034', // Auth bypass with allowInsecureAuth
  'CVE-2026-28446', // Auth bypass in voice-call extension
  'CVE-2026-28450', // Auth bypass
];

export interface SecurityCheckResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Compare two semver-like version strings (format: YYYY.M.D or YYYY.M.D.P).
 * Returns: negative if a < b, 0 if equal, positive if a > b.
 */
function compareVersions(a: string, b: string): number {
  const parseParts = (v: string) =>
    v.split('.').map((n) => parseInt(n, 10) || 0);
  const partsA = parseParts(a);
  const partsB = parseParts(b);
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const diff = (partsA[i] || 0) - (partsB[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Validate the OpenClaw core version meets minimum security requirements.
 */
export function checkCoreVersion(
  reportedVersion: string | undefined
): SecurityCheckResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!reportedVersion) {
    errors.push(
      'Cannot determine OpenClaw version. ' +
        `Minimum required: ${MIN_SAFE_VERSION}. ` +
        'Refusing to start on unknown version.'
    );
    return { passed: false, errors, warnings };
  }

  if (compareVersions(reportedVersion, MIN_SAFE_VERSION) < 0) {
    errors.push(
      `OpenClaw version ${reportedVersion} is below minimum safe version ${MIN_SAFE_VERSION}. ` +
        `This version is vulnerable to: ${PATCHED_CVES.join(', ')}. ` +
        'Upgrade OpenClaw before using this plugin.'
    );
  }

  return { passed: errors.length === 0, errors, warnings };
}

/**
 * Validate device pairing configuration for known insecure settings.
 */
export function checkPairingSecurity(config: {
  allowInsecureAuth?: boolean;
  pairingRequired?: boolean;
  approvedDevicesOnly?: boolean;
}): SecurityCheckResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // CVE-2026-32034: allowInsecureAuth bypass
  if (config.allowInsecureAuth === true) {
    errors.push(
      'allowInsecureAuth is enabled. This allows auth bypass (CVE-2026-32034). ' +
        'Set allowInsecureAuth to false or remove it.'
    );
  }

  // Warn if no device authentication is enforced
  if (config.pairingRequired === false || config.approvedDevicesOnly === false) {
    warnings.push(
      'Device pairing/authentication is disabled. ' +
        '6 CVEs in 2026 targeted the pairing flow. ' +
        'Enable pairingRequired and approvedDevicesOnly for production.'
    );
  }

  return { passed: errors.length === 0, errors, warnings };
}

/**
 * Full startup security posture check.
 */
export function runStartupChecks(params: {
  coreVersion?: string;
  pairingConfig?: {
    allowInsecureAuth?: boolean;
    pairingRequired?: boolean;
    approvedDevicesOnly?: boolean;
  };
}): SecurityCheckResult {
  const versionResult = checkCoreVersion(params.coreVersion);
  const pairingResult = checkPairingSecurity(params.pairingConfig || {});

  const allErrors = [...versionResult.errors, ...pairingResult.errors];
  const allWarnings = [...versionResult.warnings, ...pairingResult.warnings];

  return {
    passed: allErrors.length === 0,
    errors: allErrors,
    warnings: allWarnings,
  };
}
