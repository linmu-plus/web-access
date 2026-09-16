// test/confirm.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeConfirm, checkConfirm } from '../scripts/confirm-lib.mjs';

function tmp() { return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wa-cfm-')), 'confirm.token'); }

test('生成 → 校验放行 → 用后即焚 → 复用被拒', () => {
  const file = tmp();
  const rec = writeConfirm('在 X 站点上传 3 张图片', 120, file);
  assert.match(rec.code, /^[0-9a-f]{16}$/);
  assert.equal(checkConfirm(rec.code, { filePath: file }), null);
  const r2 = checkConfirm(rec.code, { filePath: file });
  assert.equal(r2.status, 403);
  assert.match(r2.error, /没有待确认/);
});

test('过期 code → 拒绝且文件清除', () => {
  const file = tmp();
  const rec = writeConfirm('test', 120, file);
  const r = checkConfirm(rec.code, { filePath: file, now: Date.now() + 121_000 });
  assert.equal(r.status, 403);
  assert.match(r.error, /已过期/);
  assert.equal(fs.existsSync(file), false);
});

test('code 不匹配 → 拒绝但保留文件（不是攻击者销毁证据）', () => {
  const file = tmp();
  const rec = writeConfirm('test', 120, file);
  const r = checkConfirm('deadbeefdeadbeef', { filePath: file });
  assert.equal(r.status, 403);
  assert.equal(fs.existsSync(file), true);
});

test('无待确认文件 → 拒绝', () => {
  const r = checkConfirm('anything', { filePath: tmp() });
  assert.equal(r.status, 403);
});
