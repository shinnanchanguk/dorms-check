// 사용자에게 보이는 안내 문구는 모두 templates/copy.ko.json 한 곳에서 읽는다(형이 한곳에서 고친다).
// t('a.b.c', {vars}) → 문자열. 키가 없으면 오류를 던진다(빠진 문구가 조용히 새지 않게).
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const COPY_PATH = fileURLToPath(new URL('../templates/copy.ko.json', import.meta.url));
let cache = null;

export function loadCopy() {
  if (!cache) cache = JSON.parse(readFileSync(COPY_PATH, 'utf8'));
  return cache;
}

export function copyValue(key) {
  let cur = loadCopy();
  for (const part of key.split('.')) {
    if (cur === null || typeof cur !== 'object' || !(part in cur)) throw new Error(`copy.ko.json 에 문구 키가 없습니다: ${key}`);
    cur = cur[part];
  }
  return cur;
}

export function fillVars(tpl, vars = {}) {
  return String(tpl).replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined && vars[k] !== null ? String(vars[k]) : ''));
}

export function t(key, vars) {
  const v = copyValue(key);
  if (typeof v !== 'string') throw new Error(`문구 키가 문자열이 아닙니다: ${key}`);
  return fillVars(v, vars);
}
