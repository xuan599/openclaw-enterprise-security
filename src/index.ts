/**
 * OpenClaw Enterprise Security Plugin
 *
 * Default-deny tool policy + audit logging + data sensitivity routing
 * + device pairing guard (CVE-2026-33579 and related).
 *
 * Install: openclaw plugin add @enterprise/security
 * Config: openclaw.json -> plugins.entries.enterprise-security.config
 */

import { PolicyEngine } from './policy-engine';
import { AuditLogger, AuditEntry } from './audit-logger';
import { SensitivityRouter, SensitivityLevel } from './sensitivity-router';
import { runStartupChecks } from './security-checks';
import { validateConfig, ValidatedPluginConfig } from './config';
import { PairingGuard } from './pairing-guard';

// Types for the Plugin SDK API object
// These mirror the real SDK types but are declared locally
// to avoid hard dependency at compile time.
interface OpenClawPluginApi {
  id: string;
  name: string;
  version?: string;
  logger: {
    info: (msg: string, ...args: unknown[]) => void;
    warn: (msg: string, ...args: unknown[]) => void;
    error: (msg: string, ...args: unknown[]) => void;
    debug: (msg: string, ...args: unknown[]) => void;
  };
  pluginConfig: Record<string, unknown>;
  on(hookName: string, handler: (ctx: unknown) => Promise<unknown>, opts?: unknown): void;
  registerService(service: { name: string; start: () => Promise<void>; stop: () => Promise<void> }): void;
}

interface ToolCallContext {
  tool: string;
  args?: Record<string, unknown>;
  input?: string;
  user?: string;
  userRole?: 'admin' | 'user';
  sessionId?: string;
}

export default function enterpriseSecurityPlugin(api: OpenClawPluginApi): void {
  // Validate config via zod - throws on malicious/invalid input
  let config: ValidatedPluginConfig;
  try {
    config = validateConfig(api.pluginConfig || {});
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Enterprise Security Plugin: invalid config — ${msg}`);
  }

  // --- Startup security posture check ---
  const securityResult = runStartupChecks({
    coreVersion: api.version,
    pairingConfig: config.pairing,
  });

  if (!securityResult.passed) {
    for (const err of securityResult.errors) {
      api.logger.error(`SECURITY BLOCKER: ${err}`);
    }
    throw new Error(
      'Enterprise Security Plugin refuses to start due to security violations:\n' +
        securityResult.errors.join('\n')
    );
  }
  for (const warn of securityResult.warnings) {
    api.logger.warn(`SECURITY WARNING: ${warn}`);
  }

  // Initialize engines
  const policyEngine = new PolicyEngine(config.policy);
  const auditLogger = new AuditLogger(config.audit?.logDir);
  const sensitivityRouter = new SensitivityRouter(config.sensitivity);
  const pairingGuard = new PairingGuard(config.pairingGuard || {}, auditLogger);

  api.logger.info('Enterprise Security Plugin initializing...');
  api.logger.info(`Policy mode: ${policyEngine.getConfig().mode}`);
  api.logger.info(`Audit log: ${auditLogger.getLogPath()}`);
  api.logger.info(`Pairing guard: ${pairingGuard.getConfig().pairingRequired ? 'ENFORCED' : 'DISABLED'}`);

  // Periodic cleanup of expired pairing codes (every 60s)
  const cleanupInterval = setInterval(() => {
    const cleaned = pairingGuard.cleanupExpiredCodes();
    if (cleaned > 0) {
      api.logger.debug(`Cleaned up ${cleaned} expired pairing codes`);
    }
  }, 60_000);

  // Register background service for lifecycle management
  api.registerService({
    name: 'enterprise-security',
    start: async () => {
      api.logger.info('Enterprise Security Plugin started');
    },
    stop: async () => {
      clearInterval(cleanupInterval);
      await auditLogger.close();
      api.logger.info('Enterprise Security Plugin stopped, audit log flushed');
    },
  });

  // Hook: before_tool_call
  // Security gate chain: pairing guard → policy → sensitivity → audit
  api.on('before_tool_call', async (ctx: unknown) => {
    const toolCtx = ctx as ToolCallContext;
    const toolName = toolCtx.tool || 'unknown';
    const inputText = [toolCtx.input, JSON.stringify(toolCtx.args || {})].join(' ');

    // 0. Device pairing guard — full validation for pairing-related tools
    if (isPairingTool(toolName)) {
      const result = pairingGuard.check(
        toolName,
        toolCtx.args,
        toolCtx.userRole
      );

      const ts = new Date().toISOString();
      if (!result.allowed) {
        api.logger.warn(`Pairing blocked: ${result.reason}`);
        auditLogger.log({
          ts,
          tool: toolName,
          decision: 'blocked',
          reason: result.reason,
          user: toolCtx.user,
          sessionId: toolCtx.sessionId,
        });
        return { block: true, reason: result.reason };
      }

      // Pairing allowed — audit it
      auditLogger.log({
        ts,
        tool: toolName,
        decision: 'allowed',
        user: toolCtx.user,
        sessionId: toolCtx.sessionId,
      });
    }

    // 1. Policy check (default-deny)
    const policyResult = policyEngine.check(toolName);
    if (policyResult) {
      api.logger.info(`Tool "${toolName}" blocked by policy: ${policyResult.reason}`);

      const entry: AuditEntry = {
        ts: new Date().toISOString(),
        tool: toolName,
        decision: 'blocked',
        reason: policyResult.reason,
        user: toolCtx.user,
        sessionId: toolCtx.sessionId,
      };
      auditLogger.log(entry);

      return { block: true, reason: policyResult.reason };
    }

    // 2. Sensitivity classification
    const sensitivity = sensitivityRouter.classify(inputText);
    const routing = sensitivityRouter.getRoutingAction(sensitivity);

    // 3. S3 blocking: if sensitive data detected and tool would send to cloud
    if (routing.forceLocal && isCloudTool(toolName)) {
      api.logger.warn(
        `Tool "${toolName}" blocked for S3 data: ${routing.reason}`
      );

      const entry: AuditEntry = {
        ts: new Date().toISOString(),
        tool: toolName,
        decision: 'blocked',
        reason: routing.reason,
        user: toolCtx.user,
        sessionId: toolCtx.sessionId,
        sensitivity,
      };
      auditLogger.log(entry);

      return { block: true, reason: routing.reason };
    }

    // 4. Allowed - log it
    const entry: AuditEntry = {
      ts: new Date().toISOString(),
      tool: toolName,
      decision: 'allowed',
      user: toolCtx.user,
      sessionId: toolCtx.sessionId,
      sensitivity: routing.audit ? sensitivity : undefined,
    };
    auditLogger.log(entry);

    // No block - allow the tool call
    return undefined;
  });
}

/**
 * Check if a tool would send data to external/cloud endpoints.
 */
function isCloudTool(toolName: string): boolean {
  const cloudTools = [
    'web_fetch',
    'web_search',
    'http_request',
    'fetch',
    'search',
    'browse',
    'email',
    'slack',
  ];
  return cloudTools.some((t) => toolName.includes(t));
}

/**
 * Check if a tool is related to device pairing operations.
 * These are the attack surface for 6+ CVEs in 2026.
 */
function isPairingTool(toolName: string): boolean {
  const pairingTools = ['pair', 'device_pair', 'approve_device', 'register_device'];
  return pairingTools.some((t) => toolName.includes(t));
}

// Re-export for testing
export { PolicyEngine } from './policy-engine';
export { AuditLogger, AuditEntry } from './audit-logger';
export { SensitivityRouter, SensitivityLevel } from './sensitivity-router';
export { PairingGuard } from './pairing-guard';
