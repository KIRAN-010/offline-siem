from src.ingestion import LogIngestor
ingestor = LogIngestor()
logs = list(ingestor.ingest_file('test_sample.txt'))
print(f'Parsed {len(logs)} logs')
for log in logs:
    print(f'  IP: {log.metadata.get("ip")}, Message: {log.message}, Level: {log.level}')