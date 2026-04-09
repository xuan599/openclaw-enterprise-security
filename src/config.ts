/**
 * Zod-based configuration validation.
 *
 * Prevents malicious config injection and provides clear error messages
 * when configuration is invalid.
 */

import { z } from 'zod';

export const PolicyConfigSchema = z.object({
  mode: z.enum(['deny', 'allow']).default('deny'),
  allowTools: z.array(z.string()).default([]),
  denyTools: z.array(z.string()).default(['exec', 'full', 'shell', 'bash']),
  allowPatterns: z.array(z.string()).default([]),
});

export const SensitivityConfigSchema = z.object({
  s3Patterns: z.array(z.union([z.string(), z.instanceof(RegExp)])).default([]),
  s2Patterns: z.array(z.union([z.string(), z.instanceof(RegExp)])).default([]),
  scanArguments: z.boolean().default(true),
});

export const AuditConfigSchema = z.object({
  logDir: z.string().default('./logs'),
});

export const PairingConfigSchema = z.object({
  allowInsecureAuth: z.boolean().optional(),
  pairingRequired: z.boolean().optional(),
  approvedDevicesOnly: z.boolean().optional(),
});

export const PairingGuardConfigSchema = z.object({
  pairingRequired: z.boolean().default(true),
  approvedDevicesOnly: z.boolean().default(true),
  pairingCodeMaxAge: z.number().int().min(0).default(300),
  approvedDevices: z.array(z.string()).default([]),
  blockNonAdminApproval: z.boolean().default(true),
});

export const PluginConfigSchema = z.object({
  policy: PolicyConfigSchema.default({}),
  sensitivity: SensitivityConfigSchema.default({}),
  audit: AuditConfigSchema.default({}),
  pairing: PairingConfigSchema.default({}),
  pairingGuard: PairingGuardConfigSchema.default({}),
});

export type ValidatedPluginConfig = z.infer<typeof PluginConfigSchema>;

/**
 * Parse and validate plugin config from raw input.
 * Throws ZodError with detailed messages if validation fails.
 */
export function validateConfig(raw: unknown): ValidatedPluginConfig {
  return PluginConfigSchema.parse(raw);
}

/**
 * Safe parse that returns a result instead of throwing.
 */
export function safeValidateConfig(raw: unknown): {
  success: boolean;
  data?: ValidatedPluginConfig;
  errors?: string[];
} {
  const result = PluginConfigSchema.safeParse(raw);
  if (result.success) {
    return { success: true, data: result.data };
  }
  const errors = result.error.errors.map(
    (e) => `${e.path.join('.')}: ${e.message}`
  );
  return { success: false, errors };
}
