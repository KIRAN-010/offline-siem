import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import { api } from './api';
vi.mock('./api', () => ({api: {dashboard: vi.fn(), alerts: vi.fn(), incidents: vi.fn(), saved: vi.fn(), hunt: vi.fn(), importLogs: vi.fn(), alertStatus: vi.fn(), incidentStatus: vi.fn(), timeline: vi.fn(), notes: vi.fn(), evidence: vi.fn(), correlate: vi.fn(), addNote: vi.fn(), saveSearch: vi.fn(), attachEvidence: vi.fn(), reportUrl: () => '/report'}}));
const incident = {incident_uid: 'INC-1', title: 'Authentication investigation', severity: 'HIGH', status: 'open', summary: 'Repeated authentication failures', risk_score: 80, risk_level: 'HIGH', attack_techniques: [{technique_id: 'T1110', tactic: 'Credential Access', technique: 'Brute Force'}]};
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.dashboard).mockResolvedValue({events: 5, alerts: 1, new_alerts: 1, alerts_by_severity: {HIGH: 1}, alerts_by_type: {}});
  vi.mocked(api.alerts).mockResolvedValue({alerts: [{alert_uid: 'A1', severity: 'HIGH', reason: 'Repeated login failures', timestamp: '2026-10-11T10:00:00Z', confidence: 1, status: 'new'}]});
  vi.mocked(api.incidents).mockResolvedValue({incidents: [incident]});
  vi.mocked(api.saved).mockResolvedValue({searches: []});
  vi.mocked(api.timeline).mockResolvedValue({incident, timeline: []});
  vi.mocked(api.notes).mockResolvedValue({notes: []});
  vi.mocked(api.evidence).mockResolvedValue({events: []});
});
describe('analyst workflows', () => {
  it('loads overview and sends alert triage changes', async () => {
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('Repeated login failures');
    await user.selectOptions(screen.getByLabelText('Status for A1'), 'acknowledged');
    await waitFor(() => expect(api.alertStatus).toHaveBeenCalledWith('A1', 'acknowledged'));
  });
  it('searches and renders normalized raw_data', async () => {
    vi.mocked(api.hunt).mockResolvedValue({events: [{id: 1, event_uid: 'E1', timestamp: '2026-10-11T10:00:00Z', source: 'sshd', source_ip: '192.0.2.1', username: 'admin', severity: 'high', command: null, process: null, raw_data: {message: 'Failed password for admin'}}]});
    const user = userEvent.setup(); render(<App/>);
    await screen.findByText('Repeated login failures');
    await user.type(screen.getByLabelText('Hunt query'), 'Failed');
    await user.click(screen.getByRole('button', {name: /^Search$/}));
    expect(await screen.findByText('Failed password for admin')).toBeInTheDocument();
    expect(api.hunt).toHaveBeenCalledWith('Failed');
  });
  it('opens investigation and persists a note', async () => {
    const user = userEvent.setup(); render(<App/>);
    await user.click(await screen.findByRole('button', {name: 'Investigate'}));
    await user.type(await screen.findByLabelText('Analyst note'), 'Investigating auth events');
    await user.click(screen.getByRole('button', {name: 'Add note'}));
    await waitFor(() => expect(api.addNote).toHaveBeenCalledWith('INC-1', 'Investigating auth events'));
    expect(screen.getByRole('link', {name: 'Download report'})).toHaveAttribute('href', '/report');
  });
  it('displays request failures without an unhandled rejection', async () => {
    vi.mocked(api.dashboard).mockRejectedValue(new Error('API is unavailable'));
    render(<App/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('API is unavailable');
  });
});

it('uploads logs and reports ingestion results', async () => {
  vi.mocked(api.importLogs).mockResolvedValue({accepted: 3, alerts_generated: 2});
  const user = userEvent.setup(); render(<App/>);
  await screen.findByText('Repeated login failures');
  const file = new File(['{"message":"example"}'], 'events.json', {type: 'application/json'});
  Object.defineProperty(file, 'text', {value: async () => '{"message":"example"}'});
  await user.upload(screen.getByLabelText('Log file'), file);
  expect((screen.getByLabelText('Log file') as HTMLInputElement).files?.[0]).toBe(file);
  fireEvent.submit(screen.getByLabelText('Log file').closest('form')!);
  expect(await screen.findByRole('status')).toHaveTextContent('3 new events stored; 2 detections generated.');
  expect(api.importLogs).toHaveBeenCalledWith('events.json', '{"message":"example"}');
});

it('saves a reusable hunt query', async () => {
  const user = userEvent.setup(); render(<App/>);
  await screen.findByText('Repeated login failures');
  await user.type(screen.getByLabelText('Hunt query'), 'powershell');
  await user.type(screen.getByLabelText('Saved search name'), 'PowerShell review');
  await user.click(screen.getByRole('button', {name: 'Save search'}));
  await waitFor(() => expect(api.saveSearch).toHaveBeenCalledWith('PowerShell review', 'powershell'));
});
