# Threat Aggregation Lab (Full Project with OTX Collector)

This is a simplified OSINT lab skeleton with OTX collector integrated.

## Quickstart

1. python -m venv venv && source venv/bin/activate
2. pip install -r requirements.txt
3. Run OTX collector:
   ```bash
   python -m src.collectors.otx_collector
   ```
4. Data will be saved under data/raw/otx/<date>.jsonl
5. Normalize data to STIX-like format:
   ```bash
   python -m src.normalizers.stix_normalizer data/raw/otx/<date>.jsonl
   ```
