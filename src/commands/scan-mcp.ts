// src/commands/scan-mcp.ts — /scan-mcp: connect to configured MCP servers and
// scan their tool definitions for poisoning + rug-pulls.
//
// Safety model (mirrors Snyk agent-scan): scanning spawns the configured stdio
// servers, so it is an explicit user action — never auto-run at startup.

import { ShellWard } from '../core/engine.js'
import { McpBaseline } from '../mcp-baseline.js'
import { discoverMcpServers, listToolsStdio, listToolsHttp } from '../mcp-client.js'
import type { ShellWardConfig } from '../types.js'
import { resolveLocale } from '../types.js'

export function registerScanMcpCommand(api: any, config: ShellWardConfig) {
  const locale = resolveLocale(config)

  api.registerCommand({
    name: 'scan-mcp',
    description: locale === 'zh'
      ? '🔌 扫描已配置的 MCP 服务器（工具投毒 + rug-pull 检测）'
      : '🔌 Scan configured MCP servers (tool poisoning + rug-pull)',
    acceptsArgs: false,
    handler: async () => {
      const zh = locale === 'zh'
      const guard = new ShellWard(config)
      const baseline = new McpBaseline()
      const lines: string[] = []

      lines.push(zh ? '🔌 **MCP 服务器安全扫描**' : '🔌 **MCP Server Security Scan**')
      lines.push('')

      const servers = discoverMcpServers()
      if (servers.length === 0) {
        lines.push(zh
          ? 'ℹ️ 未发现已配置的 MCP 服务器（检查 ~/.openclaw/mcp.json 等）。'
          : 'ℹ️ No configured MCP servers found (checked ~/.openclaw/mcp.json etc).')
        return { text: lines.join('\n') }
      }

      const stdioServers = servers.filter(s => s.transport === 'stdio')
      const remoteServers = servers.filter(s => s.transport === 'remote')

      lines.push(zh
        ? `发现 ${servers.length} 个服务器（${stdioServers.length} 个 stdio，${remoteServers.length} 个远程）`
        : `Found ${servers.length} servers (${stdioServers.length} stdio, ${remoteServers.length} remote)`)
      lines.push('')

      let totalTools = 0
      let poisoned = 0
      let rugPulls = 0
      let unreachable = 0

      for (const server of servers) {
        let tools
        try {
          tools = server.transport === 'remote'
            ? await listToolsHttp(server)
            : await listToolsStdio(server)
        } catch (e: any) {
          unreachable++
          const where = server.transport === 'remote' ? server.url || 'remote' : 'stdio'
          lines.push(zh
            ? `### ⚠️ ${server.name} (${where}) — 无法连接 (${e?.message || 'error'})`
            : `### ⚠️ ${server.name} (${where}) — unreachable (${e?.message || 'error'})`)
          lines.push('')
          continue
        }

        const serverIssues: string[] = []
        for (const tool of tools) {
          totalTools++
          const scan = guard.scanToolDefinition(tool)
          const rp = baseline.record(McpBaseline.keyFor(server.name, tool.name), tool)

          if (!scan.safe) {
            poisoned++
            serverIssues.push(zh
              ? `  🔴 \`${tool.name}\` 工具投毒 (评分 ${scan.score}): ${scan.findings.map(f => f.name).join('; ')}`
              : `  🔴 \`${tool.name}\` poisoned (score ${scan.score}): ${scan.findings.map(f => f.name).join('; ')}`)
          }
          if (rp.status === 'changed') {
            rugPulls++
            serverIssues.push(zh
              ? `  🟠 \`${tool.name}\` 描述自上次以来被修改 (rug-pull 嫌疑)`
              : `  🟠 \`${tool.name}\` description changed since last seen (possible rug-pull)`)
          }
        }

        const icon = serverIssues.length > 0 ? '🔴' : '✅'
        const tag = server.transport === 'remote' ? ' (remote)' : ''
        lines.push(`### ${icon} ${server.name}${tag}`)
        lines.push(zh ? `  ${tools.length} 个工具` : `  ${tools.length} tools`)
        if (serverIssues.length === 0) {
          lines.push(zh ? '  ✅ 未发现问题' : '  ✅ No issues found')
        } else {
          lines.push(...serverIssues)
        }
        lines.push('')
      }

      baseline.save()

      // Summary
      lines.push('---')
      lines.push(zh
        ? `扫描了 ${totalTools} 个工具 · 🔴 投毒 ${poisoned} · 🟠 rug-pull ${rugPulls} · ⚠️ 无法连接 ${unreachable}`
        : `Scanned ${totalTools} tools · 🔴 poisoned ${poisoned} · 🟠 rug-pull ${rugPulls} · ⚠️ unreachable ${unreachable}`)
      if (poisoned === 0 && rugPulls === 0) {
        lines.push(zh ? '✅ **所有 MCP 工具通过扫描**' : '✅ **All MCP tools passed**')
      } else {
        lines.push(zh
          ? '⚠️ **发现可疑 MCP 工具 — 请审查或移除对应服务器**'
          : '⚠️ **Suspicious MCP tools found — review or remove the server**')
      }

      return { text: lines.join('\n') }
    },
  })
}
