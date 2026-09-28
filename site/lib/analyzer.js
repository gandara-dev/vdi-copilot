// Browser port of the VDI Copilot redaction and rule engine.
//
// It mirrors src/vdi_copilot/redact.py and src/vdi_copilot/rules.py. The Node
// suite asserts it against tests/fixtures/analyzer-cases.json, which is
// generated from the Python package, so the page and the CLI redact and match
// the same way. Word boundaries and case folding follow ASCII rules here; the
// fixtures cover ASCII evidence, which is what VDI product logs contain.

const PATTERNS = [
  [/\b(password|passwd|pwd|secret|token)(\s*[:=]\s*)[^\s;,]+/gi, '$1$2<REDACTED>', 'credential'],
  [/\bAuthorization:\s*Bearer\s+[^\s]+/gi, 'Authorization: Bearer <REDACTED>', 'bearer token'],
  [/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '<EMAIL>', 'email address'],
  [/C:\\Users\\[^\\\s]+/gi, 'C:\\Users\\<USER>', 'user profile path'],
  [/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g, '<IP>', 'IPv4 address'],
  [/\b(?:[a-z0-9-]+\.)+(?:local|internal|corp|com|net|org|test)\b/gi, '<HOST>', 'host name'],
  [/S-1-5-21-(?:\d+-){2}\d+-\d+/g, '<SID>', 'Windows SID'],
];

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const REQUIRED_FIELDS = ['id', 'title', 'severity', 'confidence', 'all', 'any', 'none', 'recommendations'];

export class RuleError extends Error {}

export function redactText(text) {
  let redacted = text;
  for (const [pattern, replacement] of PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

// Counts what each pattern removed, for the page's redaction summary.
export function redactionSummary(text) {
  const counts = [];
  let current = text;
  for (const [pattern, replacement, label] of PATTERNS) {
    const matches = current.match(pattern);
    if (matches?.length) counts.push({ label, count: matches.length });
    current = current.replace(pattern, replacement);
  }
  return counts;
}

export function validateRules(data) {
  if (data === null || typeof data !== 'object' || Array.isArray(data) ||
      data.schema_version !== 1 || !Array.isArray(data.rules)) {
    throw new RuleError('Rule file must use schema_version 1 and contain a rules array.');
  }
  const seen = new Set();
  for (const rule of data.rules) {
    const keys = rule !== null && typeof rule === 'object' ? Object.keys(rule) : [];
    const missing = REQUIRED_FIELDS.filter((field) => !keys.includes(field)).sort();
    if (missing.length) {
      throw new RuleError(`Rule is missing fields: ${missing.join(', ')}`);
    }
    if (seen.has(rule.id)) {
      throw new RuleError(`Rule IDs must be unique: ${rule.id}`);
    }
    seen.add(rule.id);
    const empty = (value) => !value || (Array.isArray(value) && value.length === 0);
    if (empty(rule.all) && empty(rule.any)) {
      throw new RuleError(`Rule must define at least one positive matcher: ${rule.id}`);
    }
  }
  return data.rules;
}

const fold = (value) => String(value).toLowerCase();

export function evaluateRules(evidence, rules) {
  const corpus = fold(evidence.map((item) => item.text).join('\n'));
  const findings = [];
  for (const rule of rules) {
    const all = rule.all.map(fold);
    const any = rule.any.map(fold);
    const none = rule.none.map(fold);
    const matchesAll = all.every((term) => corpus.includes(term));
    const matchesAny = any.length === 0 || any.some((term) => corpus.includes(term));
    const matchesNone = !none.some((term) => corpus.includes(term));
    if (!(matchesAll && matchesAny && matchesNone)) continue;

    const positive = [...rule.all, ...rule.any].map(fold);
    findings.push({
      rule_id: String(rule.id),
      title: String(rule.title),
      severity: String(rule.severity),
      confidence: String(rule.confidence),
      evidence: evidence
        .filter((item) => positive.some((term) => fold(item.text).includes(term)))
        .map((item) => item.source),
      recommendations: rule.recommendations.map(String),
    });
  }
  const rank = (finding) => SEVERITY_ORDER[finding.severity] ?? 99;
  return findings.sort((a, b) => rank(a) - rank(b) || (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0));
}

// Returns the positive terms of a rule found in one piece of evidence, for highlighting.
export function matchedTerms(rule, text) {
  const folded = fold(text);
  return [...rule.all, ...rule.any].filter((term) => folded.includes(fold(term)));
}

export function analyze(evidence, rules, { redact = true } = {}) {
  const items = evidence.map((item) => ({
    source: item.source,
    text: redact ? redactText(item.text) : item.text,
  }));
  return {
    texts: items.map((item) => item.text),
    report: {
      schema_version: 1,
      redacted: redact,
      sources: items.map((item) => item.source),
      findings: evaluateRules(items, rules),
      explanation: null,
    },
  };
}
