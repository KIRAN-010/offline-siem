"""Offline imports, persisted analyst work and downloadable case reports."""
import html
import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field, ValidationError

from src.ingestion import LogIngestor
from .db import get_connection
from .routes_events import ingest_events
from .routes_investigation import _get_incident, incident_timeline
from .schemas import SecurityEvent

router = APIRouter(prefix='/api/v1', tags=['analyst-operations'])


class LogImport(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1, max_length=2 * 1024 * 1024)


@router.post('/imports', status_code=201)
def import_logs(payload: LogImport):
    suffix = Path(payload.filename).suffix.lower()
    if suffix not in {'.json', '.jsonl', '.csv', '.txt', '.log'}:
        raise HTTPException(400, 'Supported files: JSON, JSONL, CSV, TXT and LOG')
    events = []
    try:
        if suffix in {'.json', '.jsonl'}:
            try:
                data = json.loads(payload.content)
                records = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                records = [json.loads(line) for line in payload.content.splitlines() if line.strip()]
            if not records or not all(isinstance(record, dict) for record in records):
                raise ValueError('JSON must contain event objects')
            # Prefer the canonical API shape, retaining original fields on generic logs.
            for record in records:
                if 'timestamp' in record and 'source' in record and 'raw_data' in record:
                    events.append(SecurityEvent.model_validate(record))
                else:
                    for log in LogIngestor().ingest_content(json.dumps(record), format='json'):
                        metadata = {**record, **log.metadata, 'message': log.message}
                        events.append(_canonical(log, metadata, payload.filename))
        else:
            for log in LogIngestor().ingest_content(payload.content, filename=payload.filename):
                events.append(_canonical(log, log.metadata, payload.filename))
                if len(events) > 10000:
                    raise ValueError('Imports are limited to 10,000 events')
        if not events or len(events) > 10000:
            raise ValueError('Import must contain between 1 and 10,000 events')
    except (ValueError, ValidationError, OverflowError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return ingest_events(events)


def _canonical(log, metadata, filename):
    def field(*names):
        return next((str(metadata[n]) for n in names if metadata.get(n) is not None), None)
    return SecurityEvent(
        timestamp=log.timestamp, source=log.source or log.logger or filename,
        host=field('host', 'Computer'), username=field('username', 'user', 'User'),
        source_ip=field('source_ip', 'ip', 'SourceIp'), destination_ip=field('destination_ip', 'DestinationIp'),
        event_id=field('event_id', 'EventID'), process=field('process', 'Image'),
        command=field('command', 'CommandLine'), severity=log.level.value.lower(),
        raw_data={**metadata, 'message': log.message, 'raw_line': log.raw_line},
    )


class Note(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.get('/incidents/{uid}/notes')
def notes(uid: str):
    _get_incident(uid)
    with get_connection() as conn:
        return {'notes': [dict(r) for r in conn.execute('SELECT * FROM case_notes WHERE incident_uid = ? ORDER BY id', (uid,))]}


@router.post('/incidents/{uid}/notes', status_code=201)
def add_note(uid: str, payload: Note):
    _get_incident(uid)
    if not payload.text.strip():
        raise HTTPException(400, 'Note cannot be blank')
    with get_connection() as conn:
        cursor = conn.execute('INSERT INTO case_notes (incident_uid,text) VALUES (?,?)', (uid, payload.text.strip()))
        return {'id': cursor.lastrowid, 'text': payload.text.strip()}


class Evidence(BaseModel):
    event_uid: str = Field(min_length=1, max_length=64)


@router.get('/incidents/{uid}/evidence')
def evidence(uid: str):
    _get_incident(uid)
    with get_connection() as conn:
        rows = [dict(r) for r in conn.execute('SELECT events.* FROM events JOIN case_evidence USING(event_uid) WHERE incident_uid = ? ORDER BY timestamp', (uid,))]
    for row in rows:
        row['raw_data'] = json.loads(row['raw_data'])
    return {'events': rows}


@router.post('/incidents/{uid}/evidence', status_code=201)
def attach_evidence(uid: str, payload: Evidence):
    _get_incident(uid)
    with get_connection() as conn:
        if not conn.execute('SELECT 1 FROM events WHERE event_uid = ?', (payload.event_uid,)).fetchone():
            raise HTTPException(404, 'Event not found')
        conn.execute('INSERT OR IGNORE INTO case_evidence (incident_uid,event_uid) VALUES (?,?)', (uid, payload.event_uid))
    return {'incident_uid': uid, 'event_uid': payload.event_uid}


@router.get('/incidents/{uid}/report')
def report(uid: str, format: Literal['json', 'html', 'txt'] = 'json'):
    data = {**incident_timeline(uid), **notes(uid), 'evidence': evidence(uid)['events']}
    serialized = json.dumps(data, indent=2)
    headers = {'Content-Disposition': f'attachment; filename="{data["incident"]["incident_uid"]}.{format}"'}
    if format == 'html':
        return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><title>SentinelX Case Report</title><h1>' + html.escape(data['incident']['title']) + '</h1><pre>' + html.escape(serialized) + '</pre></html>', headers=headers)
    return Response(serialized, media_type='application/json' if format == 'json' else 'text/plain', headers=headers)


class SavedSearch(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: str = Field(min_length=1, max_length=300)


@router.get('/hunting/saved')
def saved_searches():
    with get_connection() as conn:
        return {'searches': [dict(r) for r in conn.execute('SELECT * FROM saved_searches ORDER BY name')]}


@router.post('/hunting/saved', status_code=201)
def save_search(payload: SavedSearch):
    if not payload.name.strip() or not payload.query.strip():
        raise HTTPException(400, 'Name and query cannot be blank')
    with get_connection() as conn:
        conn.execute('INSERT INTO saved_searches (name,query) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET query = excluded.query', (payload.name.strip(), payload.query.strip()))
    return {'name': payload.name.strip(), 'query': payload.query.strip()}
