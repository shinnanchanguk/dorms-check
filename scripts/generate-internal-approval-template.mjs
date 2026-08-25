import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { markdownToHwpx } from 'hwp-convert';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const source = path.join(root, 'assets', 'templates', 'school-internal-approval.md');
const destination = path.join(root, 'assets', 'forms', 'school-internal-approval-blank.hwpx');
const markdown = fs.readFileSync(source, 'utf8')
  .replaceAll('{{APP_NAME}}', '[소프트웨어 이름]')
  .replaceAll('{{APP_URL}}', '[소프트웨어 접속 주소]')
  .replaceAll('{{EDZIP_URL}}', '[에듀집 확인 완료 주소]')
  .replaceAll('{{PRIVACY_URL}}', '[개인정보처리방침 주소]')
  .replaceAll('{{APP_DESCRIPTION}}', '[소프트웨어의 목적과 주요 기능]')
  .replaceAll('{{APP_STACK}}', '[기술 구성]')
  .replaceAll('{{DETECTED_SERVICES}}', '[외부 서비스 사용 현황]')
  .replaceAll('{{PROJECT_EVIDENCE}}', '- [프로젝트에서 확인한 근거 파일과 내용을 입력하세요]')
  .replaceAll('{{LEGAL_BASIS}}', '- [관련 법령과 학교 규정을 확인해 입력하세요]')
  .trimEnd() + '\n\n---\n\nTeam DoRm · 교사 홍창욱 제작 · https://dorms.school\n';
const bytes = await markdownToHwpx(markdown, { title: '학습지원 소프트웨어 선정 심의 요청 기안 빈 양식', creator: 'Team DoRm · 교사 홍창욱' });
fs.writeFileSync(destination, Buffer.from(bytes));
console.log(destination);
