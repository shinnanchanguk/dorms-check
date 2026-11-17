// 저장소의 라이선스가 앱의 이용 범위와 어긋나는지 본다 (0.5.2, 회원 검토 높음 3).
// 이용 안내가 '먼저 허락'인데 LICENSE 가 MIT 처럼 '누구나 고쳐 쓰고 다시 퍼뜨려도 된다'면, 베끼는 사람의 AI 도
// 둘이 어긋난다고 짚는다. 조용히 '권리 안내 있음'으로 통과시키지 않고 알린다(무엇이 맞는지는 선생님이 정한다).
import path from 'node:path';
import { exists, readTextSafe, readJsonSafe } from './util.js';

const LICENSE_FILES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'LICENCE.md', 'COPYING'];
const PERMISSIVE_TEXT = [
  ['MIT', /\bMIT License\b|Permission is hereby granted, free of charge/i],
  ['Apache-2.0', /Apache License,?\s+Version 2\.0/i],
  ['BSD', /\bBSD\b.{0,40}License|Redistribution and use in source and binary forms/i],
  ['ISC', /\bISC License\b/i],
  ['MPL-2.0', /Mozilla Public License/i],
  ['CC-BY', /Creative Commons Attribution|\bCC[- ]BY\b/i],
  ['CC0', /\bCC0\b|Creative Commons Zero/i],
  ['Unlicense', /This is free and unencumbered software released into the public domain/i],
];
const PERMISSIVE_SPDX = /^(\(?\s*)?(MIT|MIT-0|Apache-2\.0|BSD-[0-9]-Clause(-[A-Za-z]+)?|0BSD|ISC|MPL-2\.0|CC-BY(-SA)?-[0-9.]+|CC0-1\.0|Unlicense|WTFPL|Zlib)\b/i;

export function licenseHolder(text) {
  const m = /Copyright\s*(?:\(c\)|©)?\s*(?:\d{4}(?:\s*[-–,]\s*\d{4})*\s*)?([^\n\r]{1,80})/i.exec(text || '');
  if (!m) return '';
  return m[1].replace(/\s+(All Rights Reserved|and contributors).*$/i, '').replace(/[.,;]+$/, '').trim();
}

// 반환: { file, kind: 'permissive'|'other'|'none', name, holder, pkgLicense, pkgPermissive }
export function detectLicense(root) {
  let file = null, text = null;
  for (const n of LICENSE_FILES) {
    const p = path.join(root, n);
    if (exists(p)) { file = n; text = readTextSafe(p) || ''; break; }
  }
  const pkg = readJsonSafe(path.join(root, 'package.json')) || {};
  const pkgLicense = typeof pkg.license === 'string' ? pkg.license.trim() : '';
  const pkgPermissive = Boolean(pkgLicense) && PERMISSIVE_SPDX.test(pkgLicense);
  let name = '', kind = file ? 'other' : 'none';
  if (text !== null) {
    for (const [n, re] of PERMISSIVE_TEXT) if (re.test(text)) { name = n; kind = 'permissive'; break; }
  }
  return { file, kind, name, holder: licenseHolder(text), pkgLicense, pkgPermissive };
}

// 이용 범위(adaptationCase)와 어긋나는지. allowed(출처만 남기면 고쳐 쓰기 허용)는 허용형과 맞으므로 경고하지 않는다.
export function licenseConflict(lic, facts) {
  const out = { permissive: false, holderMismatch: false, label: '' };
  if (!lic) return out;
  const permissiveName = lic.kind === 'permissive' ? lic.name : (lic.pkgPermissive ? lic.pkgLicense : '');
  if (permissiveName && facts && facts.case !== 'allowed') {
    out.permissive = true;
    out.label = [lic.kind === 'permissive' ? `${lic.file}(${lic.name})` : null, lic.pkgPermissive ? `package.json license: ${lic.pkgLicense}` : null].filter(Boolean).join(' · ');
  }
  const norm = s => String(s || '').toLowerCase().replace(/\s+/g, '');
  if (lic.holder && facts && facts.creator) {
    const h = norm(lic.holder), c = norm(facts.creator);
    if (h && c && !h.includes(c) && !c.includes(h)) out.holderMismatch = true;
  }
  return out;
}
