// test/find-url.test.mjs
// spec §10：find-url 单测面（strict 只读专用目录 / sqlite3 缺失显式报错的决策层）
// 覆盖 resolveBrowserDirs 的 strict/daily/off 三分支；CLI 层（--browser 过滤、die、exit）留在脚本内。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { resolveBrowserDirs } from '../scripts/find-url.mjs';
import { BROWSER_DIR } from '../scripts/paths.mjs';

// resolveBrowserDirs 的分支行为包含 stderr 提示打印；临时替换 console.error 捕获，测后还原
function captureStderr(fn) {
  const lines = [];
  const orig = console.error;
  console.error = (...a) => lines.push(a.join(' '));
  try {
    return { result: fn(), stderr: lines.join('\n') };
  } finally {
    console.error = orig;
  }
}

test('strict + 无 --daily → 恰为专用隔离实例一项 + 隔离提示', () => {
  let dirs;
  const { stderr } = captureStderr(() => { dirs = resolveBrowserDirs({ isolation: 'strict', daily: false }); });
  assert.deepEqual(dirs, [{ id: 'dedicated', label: '专用隔离实例', dir: BROWSER_DIR }]);
  assert.match(stderr, /只检索专用实例/);
  assert.doesNotMatch(stderr, /--daily：将读取/);
});

test('strict + --daily → 日常目录（existsSync 过滤，无 dedicated）+ 隐私提示', () => {
  let dirs;
  const { stderr } = captureStderr(() => { dirs = resolveBrowserDirs({ isolation: 'strict', daily: true }); });
  assert.ok(Array.isArray(dirs));
  assert.ok(dirs.length >= 0);
  assert.ok(dirs.every(d => d.id !== 'dedicated'), 'daily 场景不得混入 dedicated 专用目录');
  assert.ok(dirs.every(d => fs.existsSync(d.dir)), 'daily 场景返回的目录必须真实存在（existsSync 过滤）');
  assert.match(stderr, /--daily：将读取日常浏览器历史\/书签/);
  assert.doesNotMatch(stderr, /只检索专用实例/);
});

test('isolation=off → 同日常目录，无隐私提示无隔离提示', () => {
  let dirs;
  const { stderr } = captureStderr(() => { dirs = resolveBrowserDirs({ isolation: 'off', daily: false }); });
  assert.ok(dirs.every(d => d.id !== 'dedicated' && fs.existsSync(d.dir)));
  assert.doesNotMatch(stderr, /--daily：将读取/);
  assert.doesNotMatch(stderr, /只检索专用实例/);
});
