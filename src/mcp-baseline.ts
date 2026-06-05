// src/mcp-baseline.ts — MCP "rug-pull" detection via tool-definition baselining
//
// A rug-pull attack: an MCP tool ships a benign description, gets approved/trusted,
// then later silently swaps in a malicious description. ShellWard fingerprints each
// tool's description+schema on first sight and flags later mismatches.
//
// Zero dependencies — sha256 from node:crypto, JSON store under the audit dir.

import { createHash } from 'crypto'
import { readFileSync, writeFileSync, mkdirSync } from 'fs'
import { dirname, join } from 'path'
import { getHomeDir } from './utils.js'
import type { McpToolDefinition } from './core/engine.js'

export type RugPullStatus = 'new' | 'unchanged' | 'changed'

export interface RugPullResult {
  key: string
  status: RugPullStatus
  currentHash: string
  previousHash?: string
}

interface BaselineEntry {
  hash: string
  name: string
  ts: string
}

const DEFAULT_PATH = join(getHomeDir(), '.openclaw', 'shellward', 'mcp-baseline.json')

export class McpBaseline {
  private readonly path: string
  private store: Record<string, BaselineEntry>

  /** @param filePath override the baseline file (tests pass a temp path). */
  constructor(filePath?: string) {
    this.path = filePath || DEFAULT_PATH
    this.store = this.load()
  }

  /** Fingerprint a tool's externally-visible contract (description + schema). */
  private fingerprint(tool: McpToolDefinition): string {
    const canonical = JSON.stringify({
      description: tool.description || '',
      inputSchema: tool.inputSchema ?? null,
    })
    return createHash('sha256').update(canonical).digest('hex')
  }

  /** Stable key for a tool, namespaced by its server. */
  static keyFor(server: string, toolName: string): string {
    return `${server}::${toolName}`
  }

  /** Compare against the stored baseline WITHOUT persisting. */
  diff(key: string, tool: McpToolDefinition): RugPullResult {
    const currentHash = this.fingerprint(tool)
    const prev = this.store[key]
    if (!prev) return { key, status: 'new', currentHash }
    return {
      key,
      status: prev.hash === currentHash ? 'unchanged' : 'changed',
      currentHash,
      previousHash: prev.hash,
    }
  }

  /** Compare, then update the in-memory baseline. Call save() to persist. */
  record(key: string, tool: McpToolDefinition): RugPullResult {
    const res = this.diff(key, tool)
    this.store[key] = { hash: res.currentHash, name: tool.name, ts: new Date().toISOString() }
    return res
  }

  /** Number of tracked tools. */
  get size(): number {
    return Object.keys(this.store).length
  }

  private load(): Record<string, BaselineEntry> {
    try {
      const parsed = JSON.parse(readFileSync(this.path, 'utf8'))
      return parsed && typeof parsed === 'object' ? parsed : {}
    } catch {
      return {}
    }
  }

  /** Flush the baseline to disk (owner-only perms). Never throws. */
  save(): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 })
      writeFileSync(this.path, JSON.stringify(this.store, null, 2), { mode: 0o600 })
    } catch { /* best-effort; baselining must not break the host */ }
  }
}
