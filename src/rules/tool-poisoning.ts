// src/rules/tool-poisoning.ts — MCP tool-poisoning detection rules
//
// Tool poisoning = malicious instructions hidden in an MCP tool's *metadata*
// (description / parameter descriptions) that the LLM reads but the human never
// sees in the UI. These are distinct from generic prompt-injection in user text:
// they target the agent at tool-discovery time. Patterns below are tuned for the
// common public PoCs (Invariant Labs, MCP-Shield, Snyk agent-scan).

export interface ToolPoisonRule {
  id: string
  name: string
  pattern: RegExp
  riskScore: number
  category: 'hidden_instruction' | 'data_access' | 'exfiltration' | 'concealment' | 'shadowing'
}

export const TOOL_POISONING_RULES: ToolPoisonRule[] = [
  // ===== Hidden instruction markup =====
  {
    id: 'tp_important_tag',
    name: 'Hidden <IMPORTANT>/<system> directive in description',
    pattern: /<\s*(?:important|system|secret|instructions?|admin)\s*>/i,
    riskScore: 45,
    category: 'hidden_instruction',
  },
  {
    id: 'tp_before_using',
    name: 'Pre-tool instruction injection',
    pattern: /before\s+(?:using|calling|invoking|running)\s+(?:any\s+other|this|the|another)\s+tool/i,
    riskScore: 40,
    category: 'hidden_instruction',
  },
  {
    id: 'tp_zh_before_using',
    name: '工具描述内前置指令注入',
    pattern: /(?:在使用|调用|执行)(?:任何)?(?:其他|这个|该)?工具(?:之前|前)/,
    riskScore: 40,
    category: 'hidden_instruction',
  },

  // ===== Concealment ("don't tell the user") =====
  {
    id: 'tp_do_not_tell',
    name: 'Instruction to hide activity from user',
    pattern: /(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|notify|reveal|show)\s+(?:to\s+)?(?:the\s+)?(?:user|human|operator)/i,
    riskScore: 45,
    category: 'concealment',
  },
  {
    id: 'tp_zh_do_not_tell',
    name: '指示对用户隐藏行为',
    pattern: /(?:不要|不得|切勿|别)(?:告诉|告知|提示|通知|让)?(?:用户|使用者)(?:知道|看到|发现)?/,
    riskScore: 45,
    category: 'concealment',
  },
  {
    id: 'tp_without_user',
    name: 'Act without user knowledge/consent',
    pattern: /without\s+(?:the\s+)?(?:user'?s?\s+)?(?:knowledge|consent|awareness|noticing|telling)/i,
    riskScore: 40,
    category: 'concealment',
  },

  // ===== Sensitive data access from a tool description =====
  {
    id: 'tp_read_secrets',
    // Bare mention of a sensitive path is only weakly suspicious — legitimate
    // tools (dotenv loaders, ssh managers) and security tools name these too.
    // Scored below threshold so it must corroborate another signal to block.
    name: 'Description references sensitive files',
    pattern: /(?:~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b|\.cursor\/mcp\.json|\.npmrc|\/etc\/passwd|\.config\/.*(?:token|secret|credential))/i,
    riskScore: 25,
    category: 'data_access',
  },
  {
    id: 'tp_pass_file_contents',
    name: 'Description asks to pass file/secret contents as a parameter',
    pattern: /(?:pass|include|read|send|provide|attach)\s+(?:the\s+)?(?:full\s+)?(?:contents?|content|value)\s+of\s+(?:the\s+)?(?:file|\S*(?:key|token|secret|password|credential))/i,
    riskScore: 35,
    category: 'data_access',
  },

  // ===== Exfiltration hints =====
  {
    id: 'tp_exfil_url',
    name: 'Description instructs sending data to a URL',
    pattern: /(?:send|transmit|upload|post|exfiltrate|forward)\s+(?:it|this|the\s+\w+|data|results?)?\s*(?:to|via)\s+(?:https?:\/\/|the\s+(?:webhook|endpoint|server|url))/i,
    riskScore: 40,
    category: 'exfiltration',
  },
  {
    id: 'tp_exfiltrate_verb',
    // "exfiltrate" in a tool description is almost never benign.
    name: 'Exfiltration verb in description',
    pattern: /\bexfiltrat(?:e|ion|ing)\b/i,
    riskScore: 35,
    category: 'exfiltration',
  },
  {
    id: 'tp_sidechannel',
    // A bare side-channel hostname is weak on its own (could be documentation);
    // scored below threshold so it must accompany another signal to block.
    name: 'Known exfiltration side-channel keyword',
    pattern: /\b(?:webhook\.site|requestbin|pastebin|ngrok\.io|burpcollaborator|interact\.sh|oast\b)/i,
    riskScore: 25,
    category: 'exfiltration',
  },
]
