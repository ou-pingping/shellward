// src/types.ts — ShellWard type definitions

export interface ShellWardConfig {
  mode: 'enforce' | 'audit'
  locale: 'auto' | 'zh' | 'en'
  /** 启动时自动检查 OpenClaw 漏洞、插件风险、MCP 配置，发现问题时告警 */
  autoCheckOnStartup?: boolean
  layers: {
    promptGuard: boolean
    outputScanner: boolean
    toolBlocker: boolean
    inputAuditor: boolean
    securityGate: boolean
    outboundGuard: boolean
    dataFlowGuard: boolean
    sessionGuard: boolean
  }
  injectionThreshold: number
  /** User-supplied rules merged on top of the built-ins (additive; allowedTools wins). */
  customRules?: CustomRules
}

/** A user-defined PII/secret pattern (regex source as a string for JSON-friendliness). */
export interface CustomSensitivePattern {
  id: string
  name: string
  pattern: string
  flags?: string
  replacement?: string
}

/** A user-defined dangerous-command pattern. */
export interface CustomCommandRule {
  id: string
  pattern: string
  flags?: string
  description?: string
}

/**
 * Extension points for any platform embedding ShellWard. All fields are optional
 * and ADDITIVE on top of the built-in rules — except `allowedTools`, which always
 * wins (a tool listed there is never blocked and is treated as low-risk).
 */
export interface CustomRules {
  blockedTools?: string[]
  allowedTools?: string[]
  sensitiveTools?: string[]
  outboundTools?: string[]
  honeypotPaths?: string[]
  sensitivePatterns?: CustomSensitivePattern[]
  dangerousCommands?: CustomCommandRule[]
  injectionRules?: InjectionRule[]
}

export type ResolvedLocale = 'zh' | 'en'

export interface AuditEntry {
  ts: string
  level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  layer: 'L0' | 'L1' | 'L2' | 'L3' | 'L4' | 'L5' | 'L6' | 'L7' | 'L8'
  action: 'block' | 'redact' | 'audit' | 'detect' | 'allow' | 'inject' | 'error'
  detail: string
  tool?: string
  pattern?: string
  mode: 'enforce' | 'audit'
  [key: string]: unknown
}

export interface NamedPattern {
  name: string
  pattern: RegExp
  validate?: (match: string) => boolean
}

export interface ScanMatch {
  name: string
  preview: string
}

export interface DangerousCommandRule {
  id: string
  pattern: RegExp
  description_zh: string
  description_en: string
}

export interface ProtectedPathRule {
  id: string
  pattern: RegExp
  description_zh: string
  description_en: string
}

export interface InjectionRule {
  id: string
  name: string
  pattern: string
  flags?: string
  riskScore: number
  category: string
}

export const DEFAULT_CONFIG: ShellWardConfig = {
  mode: 'enforce',
  locale: 'auto',
  autoCheckOnStartup: true,
  layers: {
    promptGuard: true,
    outputScanner: true,
    toolBlocker: true,
    inputAuditor: true,
    securityGate: true,
    outboundGuard: true,
    dataFlowGuard: true,
    sessionGuard: true,
  },
  // 40 catches single high-confidence signals (one strong rule = a block) while
  // keeping benign "act as…"-style phrasing (≤35) safe. Calibrated against bench/.
  injectionThreshold: 40,
}

/**
 * Detect locale from system environment.
 * Returns 'zh' if LANG/LC_ALL contains 'zh', otherwise 'en'.
 */
export function resolveLocale(config: ShellWardConfig): ResolvedLocale {
  if (config.locale === 'zh') return 'zh'
  if (config.locale === 'en') return 'en'
  // auto detection
  const lang = process.env.LANG || process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANGUAGE || ''
  return /\bzh[_-]|chinese/i.test(lang) ? 'zh' : 'en'
}
