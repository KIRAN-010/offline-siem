import { afterEach, expect, it, vi } from 'vitest';
import { api } from './api';
afterEach(() => vi.unstubAllGlobals());
it('encodes hunt queries and parses event results', async () => {
  const fetcher = vi.fn().mockResolvedValue({ok: true, json: async () => ({events: []})});
  vi.stubGlobal('fetch', fetcher);
  expect(await api.hunt('a & b')).toEqual({events: []});
  expect(fetcher.mock.calls[0][0]).toContain('q=a%20%26%20b');
});
it('surfaces API validation detail', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ok: false, json: async () => ({detail: 'Unsupported file type'})}));
  await expect(api.importLogs('x.exe', 'data')).rejects.toThrow('Unsupported file type');
});
it('surfaces partial detection failure after storage', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ok: true, json: async () => ({accepted: 1, detection_errors: ['rules:invalid']})}));
  await expect(api.importLogs('x.json', '{}')).rejects.toThrow('Events stored, but detection failed');
});
