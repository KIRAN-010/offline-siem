from pathlib import Path

from src.ingestion import LogIngestor


def test_sample_file_is_parsed():
    sample = Path(__file__).with_name("test_sample.txt")
    logs = list(LogIngestor().ingest_file(sample, format="text"))

    assert len(logs) == 7
    assert logs[0].metadata.get("ip") == "192.168.1.1"
    assert "Failed login" in logs[0].message


def test_content_ingestion_handles_text():
    content = "Failed login from 10.0.0.5\nSuccessful login from 10.0.0.5\n"
    logs = list(LogIngestor().ingest_content(content, format="text"))

    assert len(logs) == 2
    assert all(log.message for log in logs)
