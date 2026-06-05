// src/mcp-client.ts — Minimal MCP client for security scanning
//
// Connects to a configured MCP server (stdio OR remote Streamable HTTP), performs
// the initialize handshake and a single tools/list call, then disconnects. Used by
// /scan-mcp to fetch tool *definitions* so they can be scanned for poisoning and
// rug-pulls. Zero dependencies (child_process + node:http/https + NDJSON framing).

import { spawn } from 'child_process'
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { request as httpRequest } from 'http'
import { request as httpsRequest } from 'https'
import { getHomeDir } from './utils.js'
import type { McpToolDefinition } from './core/engine.js'

export interface McpServerSpec {
  name: string
  /** 'stdio' servers are spawned; 'remote' servers are scanned over HTTP. */
  transport: 'stdio' | 'remote'
  command?: string
  args?: string[]
  env?: Record<string, string>
  url?: string
  headers?: Record<string, string>
  source: string
}

const CONFIG_PATHS = [
  join(getHomeDir(), '.openclaw', 'mcp.json'),
  join(getHomeDir(), '.openclaw', 'config', 'mcp.json'),
  join(getHomeDir(), '.openclaw', 'settings.json'),
]

/**
 * Discover MCP servers declared in known config files.
 * Recognizes the standard `{ "mcpServers": { name: {...} } }` shape.
 * @param paths override config paths (tests pass a temp file)
 */
export function discoverMcpServers(paths: string[] = CONFIG_PATHS): McpServerSpec[] {
  const servers: McpServerSpec[] = []
  const seen = new Set<string>()

  for (const p of paths) {
    if (!existsSync(p)) continue
    let parsed: any
    try {
      parsed = JSON.parse(readFileSync(p, 'utf8'))
    } catch {
      continue
    }
    const block = parsed?.mcpServers || parsed?.mcp?.servers
    if (!block || typeof block !== 'object') continue

    for (const [name, raw] of Object.entries<any>(block)) {
      if (seen.has(name)) continue
      seen.add(name)
      if (raw && typeof raw.command === 'string') {
        servers.push({
          name,
          transport: 'stdio',
          command: raw.command,
          args: Array.isArray(raw.args) ? raw.args.map(String) : [],
          env: raw.env && typeof raw.env === 'object' ? raw.env : undefined,
          source: p,
        })
      } else if (raw && (typeof raw.url === 'string' || typeof raw.type === 'string')) {
        servers.push({
          name,
          transport: 'remote',
          url: raw.url,
          headers: raw.headers && typeof raw.headers === 'object' ? raw.headers : undefined,
          source: p,
        })
      }
    }
  }
  return servers
}

/**
 * Spawn a stdio MCP server, initialize, and return its tool definitions.
 * Always resolves (never hangs): on error/timeout it cleans up and rejects.
 */
export function listToolsStdio(spec: McpServerSpec, timeoutMs = 8000): Promise<McpToolDefinition[]> {
  return new Promise((resolve, reject) => {
    if (!spec.command) return reject(new Error('not a stdio server'))

    let child: ReturnType<typeof spawn>
    try {
      child = spawn(spec.command, spec.args || [], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, ...(spec.env || {}) },
      })
    } catch (e) {
      return reject(e as Error)
    }

    let buf = Buffer.alloc(0)
    let settled = false

    const finish = (err: Error | null, tools?: McpToolDefinition[]) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { child.kill() } catch { /* ignore */ }
      if (err) reject(err)
      else resolve(tools || [])
    }

    const timer = setTimeout(() => finish(new Error(`timeout after ${timeoutMs}ms`)), timeoutMs)
    timer.unref?.()

    const send = (obj: unknown) => {
      try { child.stdin!.write(JSON.stringify(obj) + '\n') } catch { /* ignore */ }
    }

    child.on('error', (e) => finish(e))
    child.on('exit', () => { if (!settled) finish(new Error('server exited before tools/list')) })
    child.stderr?.on('data', () => { /* protocol uses stdout; ignore stderr logs */ })

    child.stdout!.on('data', (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk])
      while (true) {
        const nl = buf.indexOf(0x0a)
        if (nl === -1) break
        const line = buf.slice(0, nl).toString('utf8').trim()
        buf = buf.slice(nl + 1)
        if (!line) continue
        let msg: any
        try { msg = JSON.parse(line) } catch { continue }

        if (msg.id === 1 && msg.result) {
          // initialize ack → notify initialized, then request the tool list
          send({ jsonrpc: '2.0', method: 'notifications/initialized' })
          send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })
        } else if (msg.id === 2) {
          const tools: McpToolDefinition[] = Array.isArray(msg.result?.tools)
            ? msg.result.tools.map((t: any) => ({
                name: String(t.name || 'unknown'),
                description: typeof t.description === 'string' ? t.description : undefined,
                inputSchema: t.inputSchema && typeof t.inputSchema === 'object' ? t.inputSchema : undefined,
              }))
            : []
          finish(null, tools)
        }
      }
    })

    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'shellward-scan', version: '1' },
      },
    })
  })
}

// ===== Remote (Streamable HTTP) transport =====

const INIT_PARAMS = {
  protocolVersion: '2024-11-05',
  capabilities: {},
  clientInfo: { name: 'shellward-scan', version: '1' },
}

/**
 * POST a single JSON-RPC message to a Streamable-HTTP MCP endpoint and return
 * the parsed JSON-RPC response. Handles both `application/json` and
 * `text/event-stream` (SSE) response bodies. Captures the Mcp-Session-Id header.
 */
function postJsonRpc(
  url: string,
  body: unknown,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<{ json: any; sessionId?: string }> {
  return new Promise((resolve, reject) => {
    let u: URL
    try { u = new URL(url) } catch { return reject(new Error(`invalid url: ${url}`)) }
    const isHttps = u.protocol === 'https:'
    const requestFn = isHttps ? httpsRequest : httpRequest
    const payload = Buffer.from(JSON.stringify(body), 'utf8')

    const req = requestFn(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'content-length': payload.length,
          ...headers,
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          const sessionId = (res.headers['mcp-session-id'] as string) || undefined
          const text = Buffer.concat(chunks).toString('utf8')
          if ((res.statusCode || 0) >= 400) {
            return reject(new Error(`HTTP ${res.statusCode}`))
          }
          const json = parseRpcBody(text)
          if (json === undefined) return resolve({ json: null, sessionId })
          resolve({ json, sessionId })
        })
      },
    )
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error(`timeout after ${timeoutMs}ms`)))
    req.end(payload)
  })
}

/** Extract a JSON-RPC object from a JSON or SSE (text/event-stream) body. */
function parseRpcBody(text: string): any {
  const trimmed = text.trim()
  if (!trimmed) return undefined
  // Plain JSON
  if (trimmed[0] === '{' || trimmed[0] === '[') {
    try { return JSON.parse(trimmed) } catch { /* fall through to SSE */ }
  }
  // SSE: take the last non-empty `data:` line that parses as JSON
  let result: any
  for (const line of trimmed.split(/\r?\n/)) {
    const m = line.match(/^data:\s*(.*)$/)
    if (m && m[1]) {
      try { result = JSON.parse(m[1]) } catch { /* ignore */ }
    }
  }
  return result
}

/**
 * Initialize a remote MCP server over Streamable HTTP and return its tool
 * definitions. Best-effort: returns [] if the server speaks an unsupported
 * dialect. Rejects on network error / timeout.
 */
export async function listToolsHttp(spec: McpServerSpec, timeoutMs = 8000): Promise<McpToolDefinition[]> {
  if (!spec.url) throw new Error('not a remote server')
  const baseHeaders = spec.headers || {}

  const init = await postJsonRpc(spec.url, { jsonrpc: '2.0', id: 1, method: 'initialize', params: INIT_PARAMS }, baseHeaders, timeoutMs)
  const sessionHeaders = init.sessionId ? { ...baseHeaders, 'mcp-session-id': init.sessionId } : baseHeaders

  // Best-effort initialized notification (ignore failures).
  try {
    await postJsonRpc(spec.url, { jsonrpc: '2.0', method: 'notifications/initialized' }, sessionHeaders, timeoutMs)
  } catch { /* some servers don't need it */ }

  const listed = await postJsonRpc(spec.url, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, sessionHeaders, timeoutMs)
  const tools = listed.json?.result?.tools
  if (!Array.isArray(tools)) return []
  return tools.map((t: any) => ({
    name: String(t.name || 'unknown'),
    description: typeof t.description === 'string' ? t.description : undefined,
    inputSchema: t.inputSchema && typeof t.inputSchema === 'object' ? t.inputSchema : undefined,
  }))
}
