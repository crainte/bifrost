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

test('Block campaign is a separate explicit action from review-only Dismiss', () => {
  assert.match(html, /'Block campaign'/);
  assert.match(html, /'Dismiss'/);
  // Block posts to its own endpoint, with an explicit confirmation flag and the displayed pattern.
  assert.match(html, /post\('\/api\/threats\/campaigns\/block', .*pattern: c\.pattern.*confirm: true/);
  // Dismiss still uses the review-only endpoint and says so.
  assert.match(html, /post\('\/api\/threats\/campaigns\/dismiss'/);
  assert.match(html, /does NOT block anything: DNS is not changed/);
});

test('block confirmation states scope, future names and the broad marker reach', () => {
  const fn = html.match(/function blockConfirmText\(c, client\) \{([\s\S]*?)\n  \}/);
  assert.ok(fn, 'confirmation text builder exists');
  assert.match(fn[1], /for ALL clients/);
  assert.match(fn[1], /only for client/);
  assert.match(fn[1], /never been queried/);
  assert.match(fn[1], /OTHER registrable \./);
  assert.match(fn[1], /Allowlisted names and paused filtering still take precedence/);
});

test('active campaign blocks are listed apart from suppressions with status and revoke', () => {
  const section = html.match(/<section id="sec-campaign-blocks"[^>]*>([\s\S]*?)<\/section>/);
  assert.ok(section, 'campaign blocks have their own section');
  assert.match(section[1], /<tbody id="b-rows">/);
  assert.match(section[1], /<th[^>]*>Status<\/th>/);
  assert.match(html, /post\('\/api\/threats\/campaign-blocks\/revoke', \{id: b\.id\}\)/);
  // A saved rule is never presented as enforced before every resolver confirms.
  assert.match(html, /applying, not yet confirmed everywhere/);
  assert.match(html, /Could not load campaign blocks\. Their state is unknown\./);
  const sup = html.match(/<section id="sec-suppressions"[\s\S]*?<\/section>/)[0];
  assert.doesNotMatch(sup, /campaign-blocks|b-rows/);
});

test('failed application and pending revocation never get a success toast', () => {
  assert.match(html, /r\.distribution !== 'published' \? 'Saved, but distribution FAILED; retrying\.'/);
  assert.match(html, /r\.state === 'failed' \? 'Application FAILED on a resolver; retrying\.'/);
  assert.match(html, /Revocation pending; some resolvers may still block/);
  assert.match(html, /Revocation FAILED; some resolvers may still block/);
  assert.match(html, /e\.saved \? b\.pattern \+ ': revocation saved, but distribution FAILED/);
  assert.doesNotMatch(html, /toast\(b\.pattern \+ ' block revoked\.'/);
});
