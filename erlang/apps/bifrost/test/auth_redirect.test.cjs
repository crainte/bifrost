const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '../priv/templates/layout.html'), 'utf8');
const script = html.match(/<script data-auth-redirect>([\s\S]*?)<\/script>/);

async function response(status) {
  const navigations = [];
  const original = async () => ({ status });
  const context = {
    fetch: original,
    location: { replace: (url) => navigations.push(url) },
  };
  context.window = context;
  vm.runInNewContext(script?.[1] || '', context);
  const result = await context.fetch('/api/stats');
  return { navigations, result, wrapped: context.fetch !== original };
}

test('expired session redirects a background API request to login', async () => {
  assert.ok(script, 'shared layout must install the auth redirect before page scripts');
  assert.ok(html.indexOf('<script data-auth-redirect>') < html.indexOf('<body>'));
  const { navigations, result, wrapped } = await response(401);
  assert.ok(wrapped);
  assert.equal(result.status, 401);
  assert.deepEqual(navigations, ['/login']);
});

test('other API responses do not redirect', async () => {
  for (const status of [200, 403, 500]) {
    const { navigations } = await response(status);
    assert.deepEqual(navigations, []);
  }
});
