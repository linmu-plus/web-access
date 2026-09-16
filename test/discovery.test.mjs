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

test('dedicated.json 通道：无 DevToolsActivePort 时可发现', async () => {
  const server = await listen();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-dj-'));
  fs.writeFileSync(path.join(dir, 'dedicated.json'),
    JSON.stringify({ port: server.address().port, wsPath: '/devtools/browser/x', confirmedAt: new Date().toISOString() }));
  const b = await findDedicatedInstance(dir);
  server.close();
  assert.ok(b, '应通过 dedicated.json 发现专用实例');
  assert.equal(b.id, 'dedicated');
  assert.equal(b.wsPath, '/devtools/browser/x');
});

test('dedicated.json 含 pid：pid 存活 → 可发现；pid 已死（陈旧记录）→ fail-closed null', async () => {
  // 沙箱内不能 spawn 子进程（EPERM）：直接找一个 process.kill(pid,0) 确认已死的 pid（fail-closed 同一判定语义）
  const isDeadPid = (pid) => { try { process.kill(pid, 0); return false; } catch (e) { return e.code === 'ESRCH'; } };
  const deadPid = [999999, 9999999, 99999999, 999999999].find(isDeadPid);
  assert.ok(deadPid, '测试前提：找到一个确认不存在的 pid');

  const server = await listen();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-djpid-'));
  const write = (pid) => fs.writeFileSync(path.join(dir, 'dedicated.json'),
    JSON.stringify({ port: server.address().port, wsPath: '/devtools/browser/p', pid, confirmedAt: new Date().toISOString() }));
  // pid 真实存活（当前测试进程）→ 正常发现
  write(process.pid);
  const b = await findDedicatedInstance(dir);
  assert.ok(b, 'pid 存活的记录应正常发现');
  assert.equal(b.port, server.address().port);
  // pid 已死（陈旧记录）→ TCP 即使活着也 fail-closed null
  write(deadPid);
  assert.equal(await findDedicatedInstance(dir), null, 'pid 已死的陈旧记录必须 fail-closed 返回 null');
  server.close();
});

test('dedicated.json 损坏 → fail-closed 返回 null', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-djbad-'));
  fs.writeFileSync(path.join(dir, 'dedicated.json'), '{ broken');
  assert.equal(await findDedicatedInstance(dir), null);
});

test('knownBrowsers 每项都带 exePaths 非空数组', () => {
  for (const b of knownBrowsers()) assert.ok(Array.isArray(b.exePaths) && b.exePaths.length > 0, `${b.id} 缺 exePaths`);
});
