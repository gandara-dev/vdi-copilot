// Asserts the browser engine against fixtures generated from the Python package.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { analyze, matchedTerms, redactionSummary, redactText, validateRules } from '../../site/lib/analyzer.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const readJson = (relative) => JSON.parse(readFileSync(path.join(root, relative), 'utf8'));
const cases = readJson('tests/fixtures/analyzer-cases.json');
const siteData = readJson('site/data/analyzer-data.json');
const defaultRules = validateRules(siteData.rules);
const customRules = validateRules(cases.custom_rules);

for (const [index, item] of cases.redaction.entries()) {
  test(`redaction ${index + 1}: ${item.input.slice(0, 40)}`, () => {
    assert.equal(redactText(item.input), item.output);
  });
}

for (const item of cases.analyses) {
  test(`analysis: ${item.name}`, () => {
    const rules = item.rules === 'custom' ? customRules : defaultRules;
    assert.deepEqual(analyze(item.evidence, rules, { redact: item.redact }), {
      texts: item.texts,
      report: item.report,
    });
  });
}

for (const item of cases.invalid_rules) {
  test(`invalid rules: ${item.name}`, () => {
    assert.throws(() => validateRules(item.document), { message: item.error });
  });
}

test('every sample incident finds exactly its expected rule', () => {
  for (const incident of siteData.incidents) {
    const { report } = analyze(incident.files, defaultRules);
    assert.deepEqual(report.findings.map((finding) => finding.rule_id), incident.expected, incident.id);
  }
});

test('the redaction summary counts what was removed', () => {
  assert.deepEqual(redactionSummary('pwd=x at 192.0.2.1 and 198.51.100.2'), [
    { label: 'credential', count: 1 },
    { label: 'IPv4 address', count: 2 },
  ]);
});

test('matched terms are reported for highlighting', () => {
  const rule = defaultRules.find((item) => item.id === 'vda-registration-dns');
  assert.deepEqual(matchedTerms(rule, 'Citrix Desktop Service: No such host is known'), [
    'Citrix Desktop Service',
    'No such host is known',
  ]);
});
