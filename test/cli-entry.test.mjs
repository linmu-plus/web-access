// test/cli-entry.test.mjs
// isMainEntry：CLI 入口判定（junction/symlink 安全）
// 根因锁定：node 把 ESM 主模块的 import.meta.url 解析为真实路径，
// 而旧守卫用 pathToFileURL(process.argv[1]) 保留调用侧 junction 路径 → 永假 → 静默无操作。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isMainEntry } from '../scripts/paths.mjs';

const thisFile = fileURLToPath(import.meta.url);

test('真实路径 === importMetaUrl → true（直接执行的等价形态）', () => {
  assert.equal(isMainEntry(pathToFileURL(fs.realpathSync(thisFile)).href, thisFile), true);
});

test('junction 调用：argv[1]=链接路径、importMetaUrl=真实路径 → true（修复目标）', () => {
  const targetDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-entry-target-'));
  const linkPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wa-entry-link-')), 'link');
  fs.symlinkSync(targetDir, linkPath, 'junction');
  const scriptFile = path.join(linkPath, 'entry.mjs');
  fs.writeFileSync(path.join(targetDir, 'entry.mjs'), '// entry\n');
  // node 真机行为：import.meta.url 是真实路径 URL，argv[1] 是链接路径 —— 修复后应识别为 main
  assert.equal(
    isMainEntry(pathToFileURL(fs.realpathSync(scriptFile)).href, scriptFile),
    true,
  );
});

test('junction 反向：importMetaUrl 为链接形式 URL（未经真实路径解析）→ false', () => {
  const targetDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wa-entry-target-'));
  const linkPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'wa-entry-link-')), 'link');
  fs.symlinkSync(targetDir, linkPath, 'junction');
  const scriptFile = path.join(linkPath, 'entry.mjs');
  fs.writeFileSync(path.join(targetDir, 'entry.mjs'), '// entry\n');
  // 锁定语义：比较基于真实路径 —— 链接形式 URL 与 argv 的 realpath 不等 → false
  assert.equal(isMainEntry(pathToFileURL(scriptFile).href, scriptFile), false);
});

test('argvPath undefined → false（被 import 时不应触发 main）', () => {
  // 显式 undefined 走默认参数 process.argv[1]；在测试进程内临时置空以命中「无 argv[1]」分支
  const original = process.argv[1];
  process.argv[1] = undefined;
  try {
    assert.equal(isMainEntry(pathToFileURL(thisFile).href), false);
  } finally {
    process.argv[1] = original;
  }
  // import 场景：argv[1] 指向其他文件（如测试运行器）→ importMetaUrl 指向被导入脚本 → false
  const pathsFile = fileURLToPath(new URL('../scripts/paths.mjs', import.meta.url));
  assert.equal(isMainEntry(pathToFileURL(thisFile).href, pathsFile), false);
});
