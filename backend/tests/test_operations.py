import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import db, event_store

@pytest.fixture
def client(tmp_path, monkeypatch):
    path = tmp_path / 'soc.db'
    monkeypatch.setattr(db, 'DEFAULT_DB_PATH', path)
    monkeypatch.setattr(event_store, 'DEFAULT_DB_PATH', path)
    with TestClient(app) as c:
        yield c

@pytest.fixture
def case(client):
    path = Path(__file__).resolve().parents[2] / 'scenarios/ssh_bruteforce/events.jsonl'
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    r = client.post('/api/v1/events', json=events)
    assert r.status_code == 201
    assert 'detection_errors' not in r.json()
    assert r.json()['alerts_generated'] > 0
    alerts = client.get('/api/v1/alerts').json()['alerts']
    r = client.post('/api/v1/incidents', json={'title': '<script>alert(1)</script>', 'alert_uids': [a['alert_uid'] for a in alerts]})
    assert r.status_code == 201
    return r.json()['incident_uid']

def test_end_to_end_case(client, case):
    assert client.patch(f'/api/v1/incidents/{case}/status', json={'status': 'investigating'}).status_code == 200
    assert client.post(f'/api/v1/incidents/{case}/notes', json={'text': 'Investigation started'}).status_code == 201
    event = client.get('/api/v1/events').json()['events'][0]
    for _ in range(2):
        assert client.post(f'/api/v1/incidents/{case}/evidence', json={'event_uid': event['event_uid']}).status_code == 201
    assert len(client.get(f'/api/v1/incidents/{case}/evidence').json()['events']) == 1
    timeline = client.get(f'/api/v1/investigation/{case}/timeline')
    assert timeline.status_code == 200
    assert timeline.json()['timeline']
    report = client.get(f'/api/v1/incidents/{case}/report').json()
    assert report['notes'][0]['text'] == 'Investigation started'
    assert report['evidence'][0]['event_uid'] == event['event_uid']
    html = client.get(f'/api/v1/incidents/{case}/report?format=html')
    assert '<script>alert(1)</script>' not in html.text
    assert '&lt;script&gt;' in html.text
    assert client.get(f'/api/v1/incidents/{case}/report?format=txt').status_code == 200
    assert client.get(f'/api/v1/incidents/{case}/report?format=pdf').status_code == 422

def test_hunt_results_and_saved_search(client, case):
    r = client.get('/api/v1/hunting/search', params={'q': 'Failed'})
    assert r.status_code == 200
    assert r.json()['events']
    assert isinstance(r.json()['events'][0]['raw_data'], dict)
    assert client.get('/api/v1/hunting/search', params={'q': "' OR 1=1 --"}).json()['count'] == 0
    assert client.post('/api/v1/hunting/saved', json={'name': 'Auth failures', 'query': 'Failed'}).status_code == 201
    assert client.post('/api/v1/hunting/saved', json={'name': 'Auth failures', 'query': 'password'}).status_code == 201
    assert client.get('/api/v1/hunting/saved').json()['searches'][0]['query'] == 'password'

def test_import_formats_and_errors(client):
    for name, content in [('logs.csv', 'timestamp,level,message\n2026-10-11T10:00:00Z,INFO,hello\n'), ('logs.txt', '2026-10-11 10:00:00 INFO test event\n'), ('logs.json', json.dumps({'timestamp': '2026-10-11T10:00:00Z', 'message': 'hello', 'source': 'test'}))]:
        r = client.post('/api/v1/imports', json={'filename': name, 'content': content})
        assert r.status_code == 201, r.text
        assert r.json()['accepted'] >= 1
        assert 'detection_errors' not in r.json()
    assert client.post('/api/v1/imports', json={'filename': 'x.json', 'content': '{broken'}).status_code == 400
    assert client.post('/api/v1/imports', json={'filename': 'x.exe', 'content': 'abc'}).status_code == 400
    assert client.post('/api/v1/incidents', json={'title': 'Missing alerts', 'alert_uids': ['missing']}).status_code == 400
    assert client.get('/api/v1/incidents/missing/report').status_code == 404
    assert client.post('/api/v1/hunting/saved', json={'name': ' ', 'query': ' '}).status_code == 400

def test_timezones_deduplicate_same_instant(client):
    event = {'source': 'test', 'timestamp': '2026-10-11T12:00:00Z'}
    assert client.post('/api/v1/events', json=[event]).json()['accepted'] == 1
    event['timestamp'] = '2026-10-11T17:30:00+05:30'
    assert client.post('/api/v1/events', json=[event]).json()['accepted'] == 0
