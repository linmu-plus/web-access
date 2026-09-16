// test/permissions.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadPermissions, migrateLegacyConfig, profileLine, DEFAULTS } from '../scripts/permissions.mjs';

function tmpCfg(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-perm-'));
  const file = path.join(dir, 'permissions.json');
  if (content !== null) fs.writeFileSync(file, content);
  return file;
}

test('合法配置逐字段生效', () => {
  const { cfg, fileMissing } = loadPermissions(tmpCfg(JSON.stringify({
    browser: 'edge', isolation: 'strict',
    confirm: { mode: 'hard', hardEndpoints: ['/clickAt'], ttlSeconds: 60 },
    domains: { mode: 'allowlist', allow: ['example.com'] },
  })));
  assert.equal(fileMissing, false);
  assert.equal(cfg.browser, 'edge');
  assert.equal(cfg.confirm.mode, 'hard');
  assert.deepEqual(cfg.confirm.hardEndpoints, ['/clickAt']);
  assert.equal(cfg.confirm.ttlSeconds, 60);
  assert.equal(cfg.domains.mode, 'allowlist');
  assert.deepEqual(cfg.domains.allow, ['example.com']);
});

test('文件缺失 → 全默认 + fileMissing 标记', () => {
  const { cfg, fileMissing } = loadPermissions(tmpCfg(null));
  assert.equal(fileMissing, true);
  assert.deepEqual(cfg, DEFAULTS);
});

test('缺失字段回退默认（升级兼容）', () => {
  const { cfg, usedDefaults } = loadPermissions(tmpCfg(JSON.stringify({ browser: 'chrome' })));
  assert.equal(cfg.browser, 'chrome');
  assert.equal(cfg.isolation, DEFAULTS.isolation);
  assert.ok(usedDefaults.includes('isolation'));
});

test('JSON 语法错 → 硬错', () => {
  assert.throws(() => loadPermissions(tmpCfg('{ nope')), /JSON 解析失败/);
});

test('未知顶层字段 → 硬错', () => {
  assert.throws(() => loadPermissions(tmpCfg('{"hacker": true}')), /未知顶层字段/);
});

test('枚举非法 → 硬错并指出字段', () => {
  assert.throws(() => loadPermissions(tmpCfg('{"isolation":"yolo"}')), /isolation/);
  assert.throws(() => loadPermissions(tmpCfg('{"confirm":{"mode":"whatever"}}')), /confirm\.mode/);
});

test('endpoints / paths 校验', () => {
  assert.throws(() => loadPermissions(tmpCfg('{"endpoints":{"eval":false}}')), /以 \/ 开头/);
  assert.throws(() => loadPermissions(tmpCfg('{"endpoints":{"/eval":"no"}}')), /布尔/);
  assert.throws(() => loadPermissions(tmpCfg('{"paths":{"setFilesRoots":"C:/"}}')), /字符串数组/);
  const { cfg } = loadPermissions(tmpCfg('{"endpoints":{"/setFiles":false}}'));
  assert.equal(cfg.endpoints['/setFiles'], false);
});

test('嵌套段类型错误 → 硬错', () => {
  assert.throws(() => loadPermissions(tmpCfg('{"confirm":"hard"}')), /confirm/);
  assert.throws(() => loadPermissions(tmpCfg('{"domains":"allowlist"}')), /domains/);
  assert.throws(() => loadPermissions(tmpCfg('{"paths":5}')), /paths/);
});

test('未知嵌套字段 → 硬错', () => {
  assert.throws(() => loadPermissions(tmpCfg('{"confirm":{"mode":"soft","ttlSecond":5}}')), /ttlSecond/);
  assert.throws(() => loadPermissions(tmpCfg('{"paths":{"setFilesRoot":"C:/"}}')), /setFilesRoot/);
});

test('旧 config.env 迁移读取', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-mig-'));
  const legacy = path.join(dir, 'config.env');
  fs.writeFileSync(legacy, '# 注释\nWEB_ACCESS_BROWSER=edge\n');
  assert.equal(migrateLegacyConfig(legacy)?.value, 'edge');
  assert.equal(migrateLegacyConfig(path.join(dir, 'nope.env')), null);
});

test('profileLine 输出剖面', () => {
  const line = profileLine({ ...DEFAULTS, browser: 'chrome' });
  assert.match(line, /isolation=strict/);
  assert.match(line, /confirm=soft/);
  assert.match(line, /browser=chrome/);
});
