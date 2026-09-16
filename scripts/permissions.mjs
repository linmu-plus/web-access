// scripts/permissions.mjs
// permissions.json 读取 + fail-closed 校验（唯一配置真源，入 git）
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SKILL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CONFIG_PATH = path.join(SKILL_ROOT, 'permissions.json');
export const LEGACY_CONFIG_PATH = path.join(SKILL_ROOT, 'config.env');

export const DEFAULTS = Object.freeze({
  browser: '',
  isolation: 'strict',
  confirm: { mode: 'soft', hardEndpoints: ['/clickAt', '/setFiles'], ttlSeconds: 120 },
  domains: { mode: 'off', allow: [], block: [] },
  endpoints: {},
  paths: { screenshotRoot: '', setFilesRoots: [] },
});

const ENUMS = {
  browser: ['', 'chrome', 'edge'],
  isolation: ['strict', 'off'],
  'confirm.mode': ['soft', 'hard', 'off'],
  'domains.mode': ['off', 'allowlist'],
};

function fail(msg) {
  throw new Error(`permissions.json 非法：${msg}（字段说明见 docs/superpowers/specs/2026-09-15-web-access-hardening-design.md §6）`);
}
function checkEnum(key, value) {
  const allowed = ENUMS[key];
  if (allowed && !allowed.includes(value)) {
    fail(`${key} = ${JSON.stringify(value)}，合法值：${allowed.map(v => JSON.stringify(v)).join(' / ')}`);
  }
}

export function loadPermissions(filePath = CONFIG_PATH) {
  let raw = {};
  let fileMissing = false;
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') { fileMissing = true; }
    else throw new Error(`permissions.json 非法：读取失败（${e.message}）。修复文件，或删除它以使用内置默认策略。`);
  }
  if (content !== undefined) {
    try { raw = JSON.parse(content.replace(/^\uFEFF/, '')); } // 剥离 UTF-8 BOM（编辑器写 BOM 的 permissions.json 按合法 JSON 解析）
    catch (e) {
      throw new Error(`permissions.json 非法：JSON 解析失败（${e.message}）。修复文件，或删除它以使用内置默认策略。`);
    }
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('permissions.json 非法：顶层必须是 JSON 对象');
  }
  const unknown = Object.keys(raw).filter(k => !(k in DEFAULTS));
  if (unknown.length) fail(`未知顶层字段 ${unknown.join(', ')}（合法：${Object.keys(DEFAULTS).join('、')}）`);

  // 嵌套段（confirm/domains/paths）：类型校验 + 未知键校验，均先于值校验（fail-closed）
  const SEGMENTS = {
    confirm: ['mode', 'hardEndpoints', 'ttlSeconds'],
    domains: ['mode', 'allow', 'block'],
    paths: ['screenshotRoot', 'setFilesRoots'],
  };
  for (const [seg, allowed] of Object.entries(SEGMENTS)) {
    const v = raw[seg];
    if (v === undefined) continue;
    if (typeof v !== 'object' || v === null || Array.isArray(v)) fail(`${seg} 必须是对象`);
    const unknownKeys = Object.keys(v).filter(k => !allowed.includes(k));
    if (unknownKeys.length) fail(`未知嵌套字段 ${seg}.${unknownKeys.join(', ')}（合法：${allowed.join('、')}）`);
  }

  const usedDefaults = [];
  const cfg = structuredClone(DEFAULTS);

  if (raw.browser !== undefined) { checkEnum('browser', raw.browser); cfg.browser = raw.browser; } else usedDefaults.push('browser');
  if (raw.isolation !== undefined) { checkEnum('isolation', raw.isolation); cfg.isolation = raw.isolation; } else usedDefaults.push('isolation');

  const c = raw.confirm ?? {};
  if (c.mode !== undefined) { checkEnum('confirm.mode', c.mode); cfg.confirm.mode = c.mode; } else usedDefaults.push('confirm.mode');
  if (c.hardEndpoints !== undefined) {
    if (!Array.isArray(c.hardEndpoints) || c.hardEndpoints.some(v => typeof v !== 'string')) fail('confirm.hardEndpoints 必须是字符串数组');
    if (c.hardEndpoints.some(v => !v.startsWith('/'))) fail('confirm.hardEndpoints 每项需以 / 开头（如 "/clickAt"）');
    cfg.confirm.hardEndpoints = c.hardEndpoints;
  }
  if (c.ttlSeconds !== undefined) {
    if (!Number.isInteger(c.ttlSeconds) || c.ttlSeconds < 1 || c.ttlSeconds > 3600) fail('confirm.ttlSeconds 需为 1-3600 的整数');
    cfg.confirm.ttlSeconds = c.ttlSeconds;
  }

  const d = raw.domains ?? {};
  if (d.mode !== undefined) { checkEnum('domains.mode', d.mode); cfg.domains.mode = d.mode; }
  for (const k of ['allow', 'block']) {
    if (d[k] !== undefined) {
      if (!Array.isArray(d[k]) || d[k].some(v => typeof v !== 'string')) fail(`domains.${k} 必须是字符串数组`);
      cfg.domains[k] = d[k];
    }
  }

  const ep = raw.endpoints ?? {};
  if (typeof ep !== 'object' || ep === null || Array.isArray(ep)) fail('endpoints 必须是对象');
  for (const [k, v] of Object.entries(ep)) {
    if (!k.startsWith('/')) fail(`endpoints 键 "${k}" 需以 / 开头`);
    if (typeof v !== 'boolean') fail(`endpoints.${k} 需为布尔值`);
    cfg.endpoints[k] = v;
  }

  const p = raw.paths ?? {};
  if (p.screenshotRoot !== undefined && typeof p.screenshotRoot !== 'string') fail('paths.screenshotRoot 需为字符串');
  if (p.setFilesRoots !== undefined && (!Array.isArray(p.setFilesRoots) || p.setFilesRoots.some(v => typeof v !== 'string'))) fail('paths.setFilesRoots 必须是字符串数组');
  cfg.paths = { screenshotRoot: p.screenshotRoot ?? '', setFilesRoots: p.setFilesRoots ?? [] };

  return { cfg, fileMissing, usedDefaults };
}

// 读旧 config.env 的 WEB_ACCESS_BROWSER（不写环境变量，分清来源）
export function migrateLegacyConfig(legacyPath = LEGACY_CONFIG_PATH) {
  let content;
  try { content = fs.readFileSync(legacyPath, 'utf8'); } catch { return null; }
  for (const line of content.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const i = t.indexOf('=');
    if (i === -1) continue;
    if (t.slice(0, i).trim() === 'WEB_ACCESS_BROWSER') {
      const v = t.slice(i + 1).trim();
      return v ? { value: v } : null;
    }
  }
  return null;
}

export function profileLine(cfg) {
  const off = Object.entries(cfg.endpoints).filter(([, v]) => v === false).map(([k]) => `${k}×`).join(',');
  return `permissions: isolation=${cfg.isolation} confirm=${cfg.confirm.mode} domains=${cfg.domains.mode} browser=${cfg.browser || '(首次询问)'} endpoints=${off || '全开'}`;
}
