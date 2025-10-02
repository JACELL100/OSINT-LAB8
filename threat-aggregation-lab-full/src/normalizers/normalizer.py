import sys
import orjson
from pathlib import Path
from datetime import datetime, timezone

def normalize(record, source="unknown"):
    now = datetime.now(timezone.utc).isoformat()
    normed = {
        "indicator": "",
        "indicator_type": "unknown",
        "first_seen": now,
        "last_seen": now,
        "source": source,
        "confidence": "medium",
        "references": [],
        "raw": record,
    }

    # ===============================
    # Source-specific normalization
    # ===============================

    if source == "otx":
        normed.update({
            "indicator": record.get("indicator", ""),
            "indicator_type": record.get("indicator_type", "unknown"),
            "first_seen": record.get("first_seen", now),
            "last_seen": record.get("last_seen", now),
            "confidence": record.get("confidence", "medium"),
            "references": record.get("references", []),
        })

    elif source == "shodan":
        normed.update({
            "indicator": record.get("ip", ""),
            "indicator_type": "ipv4-addr",
            "first_seen": record.get("last_update", now),
            "last_seen": record.get("last_update", now),
            "confidence": "high" if record.get("ports") else "medium",
            "references": [f"https://www.shodan.io/host/{record.get('ip', '')}"],
        })

    elif source == "abuseipdb":
        normed.update({
            "indicator": record.get("ip", ""),
            "indicator_type": "ipv4-addr",
            "first_seen": record.get("lastReportedAt", now),
            "last_seen": record.get("lastReportedAt", now),
            "confidence": "high" if record.get("abuseConfidenceScore", 0) > 50 else "medium",
            "references": [f"https://www.abuseipdb.com/check/{record.get('ip', '')}"],
        })

    elif source == "greynoise":
        normed.update({
            "indicator": record.get("ip", ""),
            "indicator_type": "ipv4-addr",
            "first_seen": record.get("metadata", {}).get("first_seen", now),
            "last_seen": record.get("metadata", {}).get("last_seen", now),
            "confidence": "high" if record.get("noise", False) else "low",
            "references": [f"https://viz.greynoise.io/ip/{record.get('ip', '')}"],
        })

    elif source == "spamhaus":
        normed.update({
            "indicator": record.get("ip", ""),
            "indicator_type": "ipv4-addr",
            "confidence": "high",
            "references": ["https://www.spamhaus.org/drop/"],
        })

    elif source == "abusech":
        normed.update({
            "indicator": record.get("url", ""),
            "indicator_type": "url",
            "first_seen": record.get("date_added", now),
            "last_seen": record.get("date_added", now),
            "confidence": "high" if record.get("threat") else "medium",
            "references": ["https://urlhaus.abuse.ch/"],
        })

    elif source == "hybrid_analysis":
        normed.update({
            "indicator": record.get("sha256", ""),
            "indicator_type": "file-sha256",
            "confidence": "high" if record.get("verdict") == "malicious" else "medium",
            "references": ["https://www.hybrid-analysis.com/sample/" + record.get("sha256", "")],
        })

    elif source == "virustotal":
        normed.update({
            "indicator": record.get("id", ""),
            "indicator_type": "file-hash",
            "confidence": "high",
            "references": [record.get("links", {}).get("self", "https://www.virustotal.com/")],
        })

    return normed


def run_combined(input_file):
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"❌ File not found: {input_file}")
        sys.exit(1)

    # Output directory and file
    out_dir = Path("data/processed/combined")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / (input_path.stem + ".stix.jsonl")

    count_in, count_out = 0, 0

    # The combined file is a JSON array (not JSONL)
    with open(input_path, "rb") as f_in, open(out_file, "w", encoding="utf-8") as f_out:
        try:
            data = orjson.loads(f_in.read())
        except Exception as e:
            print(f"❌ Failed to parse JSON file: {e}")
            sys.exit(1)

        if not isinstance(data, list):
            print(f"❌ Expected a list of records in {input_file}")
            sys.exit(1)

        for record in data:
            count_in += 1
            try:
                source = record.get("source", "unknown").lower()
                normed = normalize(record, source)
                f_out.write(orjson.dumps(normed).decode("utf-8") + "\n")
                count_out += 1
            except Exception as e:
                print(f"⚠️ Skipped record #{count_in}: {e}")

    print(f"\n✅ Normalized {count_out}/{count_in} records from combined file -> {out_file}")
    return str(out_file)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python normalizer.py <combined_json_file>")
        sys.exit(1)

    print(run_combined(sys.argv[1]))
