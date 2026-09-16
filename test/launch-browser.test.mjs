// test/launch-browser.test.mjs —— launch-browser 启动器纯函数
import { test } from 'node:test';
import assert from 'node:assert';
import { detectSignedInAccount } from '../scripts/launch-browser.mjs';

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
