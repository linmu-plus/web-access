// test/discovery.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { findDedicatedInstance, selectBrowser, knownBrowsers } from '../scripts/browser-discovery.mjs';

function listen() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}
function fakeDedicated(dir, port, wsPath = '/devtools/browser/abc') {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'DevToolsActivePort'), `${port}\n${wsPath}\n`);
}

test('专用实例：端口文件存在且端口活 → 返回 ok 浏览器', async () => {
  const server = await listen();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-ded-'));
  fakeDedicated(dir, server.address().port);
  const b = await findDedicatedInstance(dir);
  assert.equal(b.id, 'dedicated');
  assert.equal(b.port, server.address().port);
  server.close();
});

test('专用实例：目录缺失/端口文件缺失 → null', async () => {
  assert.equal(await findDedicatedInstance(path.join(os.tmpdir(), 'wa-nope-' + Date.now())), null);
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-empty-'));
  assert.equal(await findDedicatedInstance(empty), null);
});

test('strict 模式：专用实例缺失 → kind no-dedicated（不碰默认路径浏览器）', async () => {
  const r = await selectBrowser(null, 'chrome', { isolation: 'strict', dedicatedDir: path.join(os.tmpdir(), 'wa-none-' + Date.now()) });
  assert.equal(r.kind, 'no-dedicated');
});

test('strict 模式：专用实例存在 → ok，source=dedicated', async () => {
  const server = await listen();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-ded2-'));
  fakeDedicated(dir, server.address().port);
  const r = await selectBrowser(null, 'chrome', { isolation: 'strict', dedicatedDir: dir });
  assert.equal(r.kind, 'ok');
  assert.equal(r.browser.id, 'dedicated');
  server.close();
});

test('knownBrowsers 每项都带 exePaths 非空数组', () => {
  for (const b of knownBrowsers()) assert.ok(Array.isArray(b.exePaths) && b.exePaths.length > 0, `${b.id} 缺 exePaths`);
});
