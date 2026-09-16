// test/auth.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { checkAuth, newToken } from '../scripts/auth.mjs';

const T = newToken();
const ok = (h) => checkAuth({ headers: h }, 'tok'.padEnd(64, 'x'), 3456);

test('正确 token + 本机 Host 放行', () => {
  const t = 'x'.repeat(64);
  assert.equal(checkAuth({ headers: { host: '127.0.0.1:3456', authorization: `Bearer ${t}` } }, t, 3456), null);
  assert.equal(checkAuth({ headers: { host: 'localhost:3456', 'x-web-access-token': t } }, t, 3456), null);
});

test('缺 token / 错 token / 非本机 Host 拒绝', () => {
  const t = 'x'.repeat(64);
  assert.equal(checkAuth({ headers: { host: '127.0.0.1:3456' } }, t, 3456)?.status, 403);
  assert.equal(checkAuth({ headers: { host: '127.0.0.1:3456', authorization: 'Bearer wrong' } }, t, 3456)?.status, 403);
  assert.equal(checkAuth({ headers: { host: 'evil.com:3456', authorization: `Bearer ${t}` } }, t, 3456)?.status, 403);
});

test('DNS rebinding 场景：Host 是攻击者域名 → 拒绝', () => {
  const t = 'x'.repeat(64);
  const r = checkAuth({ headers: { host: 'evil.com:3456', authorization: `Bearer ${t}` } }, t, 3456);
  assert.equal(r.status, 403);
  assert.match(r.error, /Host 非法/);
});

test('跨站 Origin / Sec-Fetch-Site 拒绝；curl（无这些头）不受影响', () => {
  const t = 'x'.repeat(64);
  assert.equal(checkAuth({ headers: { host: '127.0.0.1:3456', authorization: `Bearer ${t}`, origin: 'http://evil.com' } }, t, 3456)?.status, 403);
  assert.equal(checkAuth({ headers: { host: '127.0.0.1:3456', authorization: `Bearer ${t}`, 'sec-fetch-site': 'cross-site' } }, t, 3456)?.status, 403);
  assert.equal(checkAuth({ headers: { host: '127.0.0.1:3456', authorization: `Bearer ${t}`, 'sec-fetch-site': 'none' } }, t, 3456), null);
});

test('token 长度不等时不比较内容（timingSafe 安全）', () => {
  assert.equal(ok({ authorization: 'Bearer short' })?.status, 403);
});

test('newToken 是 64 位 hex 且每次不同', () => {
  const a = newToken(), b = newToken();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, b);
});
