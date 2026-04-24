from src.ingestion import LogIngestor
from src.detection import DetectionEngine

ingestor = LogIngestor()
engine = DetectionEngine()

logs = list(ingestor.ingest_file('test_sample.txt'))
print(f'Parsed {len(logs)} logs')

alerts = engine.detect_batch(logs)
print(f'Generated {len(alerts)} alerts')

for alert in alerts:
    print(f'  Alert: {alert.alert_type}, Severity: {alert.severity}, Reason: {alert.reason}')