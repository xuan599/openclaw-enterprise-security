/**
 * Default-deny tool policy engine.
 *
 * All tool calls are blocked unless explicitly allowed by the whitelist.
 * Configuration via openclaw.json plugins.entries.enterprise-security.config.
 */

import micromatch from 'micromatch';

export interface PolicyConfig {
  /** Default mode: "deny" blocks everything not in allowlist */
  mode: 'deny' | 'allow';
  /** Tools that are always allowed */
  allowTools: string[];
  /** Tools that are always blocked (takes precedence over allowTools) */
  denyTools: string[];
  /** Glob patterns for tool names (uses micromatch) */
  allowPatterns: string[];
}

const DEFAULT_CONFIG: PolicyConfig = {
  mode: 'deny',
  allowTools: [],
  denyTools: ['exec', 'full', 'shell', 'bash'],
  allowPatterns: [],
};

export class PolicyEngine {
  private config: PolicyConfig;

  constructor(userConfig: Partial<PolicyConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...userConfig };
  }

  /**
   * Check if a tool call is allowed.
   * Returns { block: true } to deny, or nothing to allow.
   */
  check(toolName: string): { block: true; reason: string } | undefined {
    // Step 1: Explicit deny list (highest priority)
    if (this.config.denyTools.includes(toolName)) {
      return { block: true, reason: `Tool "${toolName}" is in the explicit deny list` };
    }

    // Step 2: Explicit allow list
    if (this.config.allowTools.includes(toolName)) {
      return undefined; // allowed
    }

    // Step 3: Pattern matching via micromatch
    if (this.config.allowPatterns.length > 0) {
      if (micromatch.isMatch(toolName, this.config.allowPatterns)) {
        return undefined; // allowed by pattern
      }
    }

    // Step 4: Default policy
    if (this.config.mode === 'deny') {
      return { block: true, reason: `Tool "${toolName}" is not in the allow list (default-deny policy)` };
    }

    // mode === 'allow', not in any list => allowed
    return undefined;
  }

  /** Reload config at runtime */
  reload(config: Partial<PolicyConfig>): void {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Get current config */
  getConfig(): Readonly<PolicyConfig> {
    return this.config;
  }
}
