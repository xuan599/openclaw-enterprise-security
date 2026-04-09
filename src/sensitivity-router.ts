/**
 * Data sensitivity classifier and router.
 *
 * S1 = public/safe data -> pass through, no special handling
 * S2 = internal data -> audit only, still allow cloud routing
 * S3 = sensitive/secret data -> must route to local model, block cloud
 *
 * Detection is rule-based in v1. Keywords and regex patterns.
 */

export type SensitivityLevel = 'S1' | 'S2' | 'S3';

export interface SensitivityConfig {
  /** Keywords/patterns for S3 (sensitive) detection */
  s3Patterns: (string | RegExp)[];
  /** Keywords/patterns for S2 (internal) detection */
  s2Patterns: (string | RegExp)[];
  /** Whether to also scan tool arguments (not just the prompt) */
  scanArguments: boolean;
}

const DEFAULT_CONFIG: SensitivityConfig = {
  s3Patterns: [
    // Chinese financial terms
    /银行卡\s*\d/i,
    /身份证\s*\d/i,
    /密码/i,
    /口令/i,
    /私钥/i,
    /secret[_\s]?key/i,
    /access[_\s]?token/i,
    /api[_\s]?key/i,
    /password/i,
    /credential/i,
    /私密/i,
    /机密/i,
    /绝密/i,
    // PII patterns
    /\b\d{17}[\dXx]\b/,      // Chinese ID card
    /\b\d{16,19}\b/,           // Bank card number
  ],
  s2Patterns: [
    // Internal business terms
    /内部/i,
    /internal/i,
    /confidential/i,
    /仅供内部/i,
    /员工/i,
    /薪酬/i,
    /工资/i,
    /绩效考核/i,
    /财务报表/i,
    /营收/i,
    /利润/i,
    /客户名单/i,
    /合同/i,
  ],
  scanArguments: true,
};

export class SensitivityRouter {
  private config: SensitivityConfig;

  constructor(userConfig: Partial<SensitivityConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...userConfig };
  }

  /**
   * Classify the sensitivity level of input text.
   * Returns the highest (most restrictive) level found.
   */
  classify(text: string): SensitivityLevel {
    if (!text) return 'S1';

    // Check S3 first (highest priority)
    for (const pattern of this.config.s3Patterns) {
      if (typeof pattern === 'string') {
        if (text.includes(pattern)) return 'S3';
      } else {
        if (pattern.test(text)) return 'S3';
      }
    }

    // Check S2
    for (const pattern of this.config.s2Patterns) {
      if (typeof pattern === 'string') {
        if (text.includes(pattern)) return 'S2';
      } else {
        if (pattern.test(text)) return 'S2';
      }
    }

    return 'S1';
  }

  /**
   * Determine routing action based on sensitivity level.
   *
   * S1 -> allow cloud routing
   * S2 -> allow but flag for audit
   * S3 -> force local model only
   */
  getRoutingAction(level: SensitivityLevel): {
    forceLocal: boolean;
    audit: boolean;
    reason: string;
  } {
    switch (level) {
      case 'S3':
        return {
          forceLocal: true,
          audit: true,
          reason: 'S3: Sensitive data detected, forced local routing',
        };
      case 'S2':
        return {
          forceLocal: false,
          audit: true,
          reason: 'S2: Internal data detected, flagged for audit',
        };
      case 'S1':
      default:
        return {
          forceLocal: false,
          audit: false,
          reason: 'S1: Public data, no restrictions',
        };
    }
  }

  /** Reload config */
  reload(config: Partial<SensitivityConfig>): void {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }
}
