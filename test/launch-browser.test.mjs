// test/launch-browser.test.mjs —— launch-browser 启动器纯函数
import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectSignedInAccount, detectImportArtifacts } from '../scripts/launch-browser.mjs';

test('detectSignedInAccount：无 user_name → null（干净）', () => {
  const localState = JSON.stringify({
    profile: { info_cache: { 'Default': { name: '人员 1', user_name: '' }, 'Profile 1': { name: 'x' } } },
  });
  assert.equal(detectSignedInAccount(localState), null);
});

test('detectSignedInAccount：任一 entry 有 user_name → 返回账号名（已登录）', () => {
  const localState = JSON.stringify({
    profile: { info_cache: { 'Default': { user_name: '' }, 'Profile 1': { user_name: 'someone@example.com' } } },
  });
  assert.equal(detectSignedInAccount(localState), 'someone@example.com');
});

// H) 首启导入污染检测 —— detectImportArtifacts(browserDir)
function makeTempProfileDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'wa-import-test-'));
}

test('detectImportArtifacts：空目录（仅 dedicated.json，无 Local State / Preferences）→ []', () => {
  const dir = makeTempProfileDir();
  fs.writeFileSync(path.join(dir, 'dedicated.json'), '{}');
  assert.deepEqual(detectImportArtifacts(dir), []);
});

test('detectImportArtifacts：Default\\Bookmarks 文件存在 → 命中含「Bookmarks/书签」的硬信号', () => {
  const dir = makeTempProfileDir();
  fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'Default', 'Bookmarks'), '{"roots":{}}');
  const hits = detectImportArtifacts(dir);
  assert.ok(hits.length > 0);
  assert.ok(hits.some(h => /Bookmarks|书签/.test(h)), `未含 Bookmarks/书签 字样：${hits.join('；')}`);
});

test('detectImportArtifacts：Preferences signin.accounts_metadata_dict 非空 → 命中含「同步」的软信号', () => {
  const dir = makeTempProfileDir();
  fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({
    signin: { accounts_metadata_dict: { 'gaia-id-1': { email: 'someone@example.com' } } },
  }));
  const hits = detectImportArtifacts(dir);
  assert.ok(hits.some(h => h.includes('同步')), `未含「同步」字样：${hits.join('；')}`);
});

test('detectImportArtifacts：Preferences sync.has_been_enabled=true → 命中含「同步」的软信号', () => {
  const dir = makeTempProfileDir();
  fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({ sync: { has_been_enabled: true } }));
  const hits = detectImportArtifacts(dir);
  assert.ok(hits.some(h => h.includes('同步')), `未含「同步」字样：${hits.join('；')}`);
});

test('detectImportArtifacts：Preferences 为坏的 JSON → 不抛错、该项未命中', () => {
  const dir = makeTempProfileDir();
  fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), '{not-json');
  assert.doesNotThrow(() => detectImportArtifacts(dir));
  assert.deepEqual(detectImportArtifacts(dir), []);
});

test('detectImportArtifacts：Preferences 存在但 accounts_metadata_dict 为空对象 → 未命中', () => {
  const dir = makeTempProfileDir();
  fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({ signin: { accounts_metadata_dict: {} } }));
  assert.deepEqual(detectImportArtifacts(dir), []);
});
