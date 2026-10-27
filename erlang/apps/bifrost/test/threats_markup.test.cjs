const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '../priv/templates/threats.html'), 'utf8');

test('active suppressions has a padded, styled section heading like campaigns', () => {
  const section = html.match(/<section id="sec-suppressions" class="st-section" aria-labelledby="suppressions-title">([\s\S]*?)<\/section>/);
  assert.ok(section, 'suppressions must have their own styled section');
  assert.match(section[1], /<header class="st-section__head">\s*<h2 id="suppressions-title">Active suppressions<\/h2>\s*<\/header>/);
  assert.match(section[1], /<tbody id="s-rows">/);
});
