// test/launch-browser.test.mjs —— launch-browser 启动器纯函数
import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { detectSignedInAccount, detectImportArtifacts, shouldRunImportCheck, collectPids } from '../scripts/launch-browser.mjs';

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
// M2：mkdtemp 临时目录在用例尾部统一清理，不向 os.tmpdir() 遗留垃圾。
function withTempProfileDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-import-test-'));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('detectImportArtifacts：空目录（仅 dedicated.json，无 Local State / Preferences）→ []', () => {
  withTempProfileDir((dir) => {
    fs.writeFileSync(path.join(dir, 'dedicated.json'), '{}');
    assert.deepEqual(detectImportArtifacts(dir), []);
  });
});

test('detectImportArtifacts：Default\\Bookmarks 文件存在 → 命中含「Bookmarks/书签」的硬信号', () => {
  withTempProfileDir((dir) => {
    fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Default', 'Bookmarks'), '{"roots":{}}');
    const hits = detectImportArtifacts(dir);
    assert.ok(hits.length > 0);
    assert.ok(hits.some(h => /Bookmarks|书签/.test(h)), `未含 Bookmarks/书签 字样：${hits.join('；')}`);
  });
});

test('detectImportArtifacts：Preferences signin.accounts_metadata_dict 非空 → 命中含「同步」的软信号', () => {
  withTempProfileDir((dir) => {
    fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({
      signin: { accounts_metadata_dict: { 'gaia-id-1': { email: 'someone@example.com' } } },
    }));
    const hits = detectImportArtifacts(dir);
    assert.ok(hits.some(h => h.includes('同步')), `未含「同步」字样：${hits.join('；')}`);
  });
});

test('detectImportArtifacts：Preferences sync.has_been_enabled=true → 命中含「同步」的软信号', () => {
  withTempProfileDir((dir) => {
    fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({ sync: { has_been_enabled: true } }));
    const hits = detectImportArtifacts(dir);
    assert.ok(hits.some(h => h.includes('同步')), `未含「同步」字样：${hits.join('；')}`);
  });
});

test('detectImportArtifacts：Preferences 为坏的 JSON → 不抛错、该项未命中', () => {
  withTempProfileDir((dir) => {
    fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), '{not-json');
    assert.doesNotThrow(() => detectImportArtifacts(dir));
    assert.deepEqual(detectImportArtifacts(dir), []);
  });
});

test('detectImportArtifacts：Preferences 存在但 accounts_metadata_dict 为空对象 → 未命中', () => {
  withTempProfileDir((dir) => {
    fs.mkdirSync(path.join(dir, 'Default'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({ signin: { accounts_metadata_dict: {} } }));
    assert.deepEqual(detectImportArtifacts(dir), []);
  });
});

// I2）导入检测门控 —— shouldRunImportCheck({ dirExists, defaultExists })
// 事故形态：目录存在但只有脚手架（早前尝试留下的 First Run/空组件目录，无 Default），
// 旧判据 `!fs.existsSync(BROWSER_DIR)` 会把这种目录判为非 fresh → 整个跳过导入检测，
// 而浏览器仍可能按首启自动导入。用户手动数据全在 Default\ 下，无 Default 即无用户数据可误杀。
test('shouldRunImportCheck：目录不存在 → fresh（应跑导入检测）', () => {
  assert.equal(shouldRunImportCheck({ dirExists: false, defaultExists: false }), true);
});

test('shouldRunImportCheck：目录存在且 Default 存在 → 非 fresh（跳过检测，保护用户手动数据）', () => {
  assert.equal(shouldRunImportCheck({ dirExists: true, defaultExists: true }), false);
});

test('shouldRunImportCheck：目录存在但无 Default（只有脚手架）→ fresh（应跑导入检测，I2 事故形态）', () => {
  assert.equal(shouldRunImportCheck({ dirExists: true, defaultExists: false }), true);
});

// M4）kill/purge 处 pid 去重 —— collectPids(recordedPid, childPid)
test('collectPids：recordedPid 与 childPid 相同 → 去重为单个（同一 pid 只 kill 一次）', () => {
  assert.deepEqual(collectPids(1234, 1234), [1234]);
});

test('collectPids：不同 pid 都保留；null/undefined 过滤；顺序 recordedPid 在前', () => {
  assert.deepEqual(collectPids(null, 5678), [5678]);
  assert.deepEqual(collectPids(1234, null), [1234]);
  assert.deepEqual(collectPids(1234, 5678), [1234, 5678]);
  assert.deepEqual(collectPids(null, null), []);
});
