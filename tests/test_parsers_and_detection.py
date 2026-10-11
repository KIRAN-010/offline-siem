from datetime import datetime, timedelta

from src.detection import DetectionEngine
from src.detection.brute_force import BruteForceDetector
from src.detection.alert import AlertType
from src.parsers.csv_parser import CSVParser
from src.parsers.json_parser import JSONParser
from src.schema import NormalizedLog, LogLevel


def test_json_parser_handles_unknown_level_without_crashing():
    logs = list(JSONParser().parse('{"timestamp":"2026-08-25T10:00:00Z","level":"NOTICE","message":"hello","ip":"192.0.2.10"}'))
    assert len(logs) == 1
    assert logs[0].level == LogLevel.UNKNOWN
    assert logs[0].metadata["ip"] == "192.0.2.10"
    assert logs[0].timestamp.tzinfo is None


def test_json_parser_handles_array_and_jsonl():
    content = '[{"message":"a"},{"message":"b"}]'
    assert len(list(JSONParser().parse(content))) == 2
    jsonl = '{"message":"a"}\n{"message":"b"}\n'
    assert len(list(JSONParser().parse(jsonl))) == 2


def test_csv_parser_handles_unknown_level():
    content = 'timestamp,level,message,ip\n2026-08-25T10:00:00Z,NOTICE,hello,192.0.2.10\n'
    logs = list(CSVParser().parse(content))
    assert len(logs) == 1
    assert logs[0].level == LogLevel.UNKNOWN


def test_bruteforce_alerts_at_threshold_without_baseline():
    start = datetime(2026, 8, 25, 10, 0, 0)
    logs = [
        NormalizedLog(start + timedelta(seconds=i * 10), LogLevel.WARNING, "login failed", metadata={"ip": "192.0.2.55"}, raw_line=f"failed {i}")
        for i in range(5)
    ]
    alerts = list(BruteForceDetector(threshold=5, window_seconds=300).detect(iter(logs)))
    assert alerts
    assert alerts[0].alert_type == AlertType.BRUTE_FORCE


def test_detection_engine_runs_multiple_detectors():
    start = datetime(2026, 8, 25, 10, 0, 0)
    logs = [
        NormalizedLog(start + timedelta(seconds=i), LogLevel.ERROR, "login failed; SQL injection", metadata={"ip": "185.220.101.1", "username": "admin"}, raw_line="attack")
        for i in range(5)
    ]
    alerts = DetectionEngine(enable_anomaly=False).detect_batch(logs)
    types = {a.alert_type for a in alerts}
    assert AlertType.BRUTE_FORCE in types
    assert AlertType.SUSPICIOUS_KEYWORD in types
    assert AlertType.SUSPICIOUS_IP in types


def test_streaming_csv_keeps_header_and_multiline_values(tmp_path):
    from src.ingestion import LogIngestor
    path = tmp_path / 'logs.csv'
    path.write_text('timestamp,level,message\n2026-10-11T10:00:00Z,INFO,"first\nsecond"\n')
    logs = list(LogIngestor().ingest_file_streaming(path))
    assert len(logs) == 1
    assert logs[0].message == 'first\nsecond'


def test_streaming_json_document(tmp_path):
    import json
    from src.ingestion import LogIngestor
    path = tmp_path / 'logs.json'
    path.write_text(json.dumps([{'message': 'one'}, {'message': 'two'}], indent=2))
    assert [log.message for log in LogIngestor().ingest_file_streaming(path)] == ['one', 'two']


def test_incremental_ingestion_returns_iterator_and_offset(tmp_path):
    from src.ingestion import LogIngestor
    path = tmp_path / 'test.log'
    path.write_text('one\npartial')
    ingestor = LogIngestor()
    events, offset = ingestor.ingest_incremental(path, format='text')
    assert [log.message for log in events] == ['one']
    assert offset == 4
    with path.open('a') as handle:
        handle.write(' completed\n')
    events, next_offset = ingestor.ingest_incremental(path, offset, format='text')
    assert [log.message for log in events] == ['partial completed']
    assert next_offset == path.stat().st_size
    path.write_text('new\n')
    events, _ = ingestor.ingest_incremental(path, next_offset, format='text')
    assert [log.message for log in events] == ['new']
