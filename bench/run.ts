#!/usr/bin/env npx tsx
// bench/run.ts — ShellWard detection benchmark.
//
// Runs every detector over the labeled corpus and reports precision/recall/F1
// per category plus the actual false positives & false negatives (the
// actionable part — those are the rows to go fix).
//
//   npm run bench           # report metrics, always exit 0
//   npm run bench -- --ci   # exit 1 if any category F1 < MIN_F1 (regression gate)

import { ShellWard } from '../src/core/engine'
import { CORPUS, type Sample, type Category } from './corpus'

const MIN_F1 = 0.85 // CI regression floor
const ci = process.argv.includes('--ci')

const guard = new ShellWard({ mode: 'enforce', locale: 'en' })

/** Returns true if the detector flags the input as malicious/sensitive. */
function detect(s: Sample): boolean {
  switch (s.category) {
    case 'injection':       return !guard.checkInjection(s.input).safe
    case 'command':         return !guard.checkCommand(s.input).allowed
    case 'pii':             return guard.scanData(s.input).hasSensitiveData
    case 'tool_poisoning':  return !guard.scanToolDefinition({ name: 'tool', description: s.input }).safe
  }
}

interface Metrics { tp: number; fp: number; fn: number; tn: number }
const empty = (): Metrics => ({ tp: 0, fp: 0, fn: 0, tn: 0 })

const byCat = new Map<Category, Metrics>()
const falsePos: Sample[] = []
const falseNeg: Sample[] = []

// Known-limitation samples are scored separately and excluded from the gate.
const gated = CORPUS.filter(s => !s.knownLimitation)
const limitations = CORPUS.filter(s => s.knownLimitation)

for (const s of gated) {
  const predicted = detect(s)
  const m = byCat.get(s.category) ?? empty()
  if (s.malicious && predicted) m.tp++
  else if (s.malicious && !predicted) { m.fn++; falseNeg.push(s) }
  else if (!s.malicious && predicted) { m.fp++; falsePos.push(s) }
  else m.tn++
  byCat.set(s.category, m)
}

let limitationsCaught = 0
for (const s of limitations) if (detect(s)) limitationsCaught++

function prf(m: Metrics) {
  const precision = m.tp + m.fp === 0 ? 1 : m.tp / (m.tp + m.fp)
  const recall = m.tp + m.fn === 0 ? 1 : m.tp / (m.tp + m.fn)
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall)
  return { precision, recall, f1 }
}

const pct = (n: number) => (n * 100).toFixed(1).padStart(5) + '%'

console.log('\n🔬 ShellWard Detection Benchmark\n')
console.log('  category         samples   precision   recall      F1   (TP/FP/FN/TN)')
console.log('  ' + '─'.repeat(72))

const overall = empty()
let worstF1 = 1
for (const [cat, m] of byCat) {
  const { precision, recall, f1 } = prf(m)
  worstF1 = Math.min(worstF1, f1)
  overall.tp += m.tp; overall.fp += m.fp; overall.fn += m.fn; overall.tn += m.tn
  const n = m.tp + m.fp + m.fn + m.tn
  console.log(`  ${cat.padEnd(16)} ${String(n).padStart(5)}    ${pct(precision)}   ${pct(recall)}  ${pct(f1)}   (${m.tp}/${m.fp}/${m.fn}/${m.tn})`)
}

console.log('  ' + '─'.repeat(72))
const o = prf(overall)
const oN = overall.tp + overall.fp + overall.fn + overall.tn
console.log(`  ${'OVERALL'.padEnd(16)} ${String(oN).padStart(5)}    ${pct(o.precision)}   ${pct(o.recall)}  ${pct(o.f1)}   (${overall.tp}/${overall.fp}/${overall.fn}/${overall.tn})`)

if (falseNeg.length) {
  console.log(`\n  ❌ False negatives (missed attacks — ${falseNeg.length}):`)
  for (const s of falseNeg) console.log(`     [${s.category}] ${truncate(s.input)}`)
}
if (falsePos.length) {
  console.log(`\n  ⚠️  False positives (benign flagged — ${falsePos.length}):`)
  for (const s of falsePos) console.log(`     [${s.category}] ${truncate(s.input)}${s.note ? `  — ${s.note}` : ''}`)
}
if (!falseNeg.length && !falsePos.length) {
  console.log('\n  ✅ No false positives or negatives on the gated corpus.')
}

if (limitations.length) {
  console.log(`\n  📋 Known limitations (documented, NOT gated): ${limitationsCaught}/${limitations.length} incidentally caught`)
  for (const s of limitations) {
    console.log(`     ${detect(s) ? '✓' : '·'} [${s.category}] ${truncate(s.input)}${s.note ? `  — ${s.note}` : ''}`)
  }
}

console.log()

if (ci && worstF1 < MIN_F1) {
  console.error(`  ❌ CI gate: lowest category F1 ${(worstF1 * 100).toFixed(1)}% < ${(MIN_F1 * 100)}% floor`)
  process.exit(1)
}

function truncate(s: string): string {
  const oneLine = s.replace(/\s+/g, ' ')
  return oneLine.length > 70 ? oneLine.slice(0, 70) + '…' : oneLine
}
