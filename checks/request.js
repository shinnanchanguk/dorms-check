import { request } from '../core/http.js';

// All probes share one deadline. Optional checks may stop without losing the main page observation.
export function createScanRequest(options = {}) {
  const deadlineAt = options.deadlineAt ?? Date.now() + (options.totalTimeout || 45000);
  return (url, requestOptions = {}) => {
    const remaining = deadlineAt - Date.now();
    if (remaining <= 0) return Promise.resolve({ ok: false, status: 0, headers: {}, body: '', finalUrl: url, error: '점검 시간 내에 확인하지 못했습니다.', aborted: true });
    return request(url, {
      ...requestOptions,
      fetchImpl: options.fetchImpl || globalThis.fetch,
      timeout: Math.min(remaining, requestOptions.timeout || 8000, options.timeout || 8000),
    });
  };
}
