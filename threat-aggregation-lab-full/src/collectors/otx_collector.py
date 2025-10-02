from pathlib import Path
from datetime import datetime, timezone
import orjson as json
import requests

# ========================
# API KEYS (embedded)
# ========================
OTX_API_KEY = "218f217a8dc00611e72954e0ec2018be0966869205e1ca48b21075d50f50bf60"
SHODAN_API_KEY = "98p3eih4UwORNmsL11q2VUKuS1ASCWBF"
ABUSEIPDB_API_KEY = "52579e2fa9c115e3df3b4a0e33a8858b412d08ef268638ac264223d600fec812a3c0f936b395aee5"
GREYNOISE_API_KEY = "74e85c27-535a-46e8-bd34-838d65691f31"

# Additional keys
SPAMHAUS_API_KEY = "RGNhTHowbGVqMU9pYjB6eWQ1ZGwySU4wOVlSM2QyVW9JeWFYbDFmak5yVS4xYTUxODkzMC1hOTBmLTRlNWYtOTM2ZC1hMWVhOWZmZDk3YWU"
ABUSECH_API_KEY = "79e8bb52c0db75a7afb034b47548eb5537a75b63b4ae3d9d"
HYBRID_API_KEY = "ntvx1oxd4093c772xfrmwu00d756acb2rf3iryke1978ac9f5o0xggmkdebe5c71"
VT_API_KEY = "20a1236353df8765716a8524e4f2958261014e0cabab6d8fbdc3ea7a92a1faf3"

# ========================
# Common helper
# ========================

def save_jsonl(data, source):
    """Save list of dicts to a JSONL file under data/raw/<source>/"""
    out_dir = Path(f"data/raw/{source}")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_file = out_dir / f"{stamp}.jsonl"

    with open(out_file, "ab") as f:
        for record in data:
            f.write(json.dumps(record))
            f.write(b"\n")

    return str(out_file)


# ========================
# Collectors
# ========================

def collect_otx():
    """Collect indicators from AlienVault OTX"""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()

    results = []
    for pulse in data.get("results", []):
        for ioc in pulse.get("indicators", []):
            results.append({
                "indicator": ioc.get("indicator", ""),
                "indicator_type": ioc.get("type", "unknown"),
                "first_seen": ioc.get("created", pulse.get("created")),
                "last_seen": ioc.get("modified", pulse.get("modified")),
                "source": "otx",
                "confidence": pulse.get("indicator_count", "medium"),
                "references": pulse.get("references", []),
            })
    return save_jsonl(results, "otx")


def collect_shodan():
    """Collect data from Shodan"""
    base_url = "https://api.shodan.io"
    headers = {"Accept": "application/json"}
    ips = ["8.8.8.8", "1.1.1.1", "4.2.2.2"]
    results = []

    for ip in ips:
        url = f"{base_url}/shodan/host/{ip}?key={SHODAN_API_KEY}"
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            results.append({
                "ip": data.get("ip_str", ip),
                "ports": data.get("ports", []),
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "country": data.get("country_name", ""),
                "last_update": data.get("last_update", datetime.now(timezone.utc).isoformat()),
                "source": "shodan"
            })
        else:
            print(f"⚠️ Skipped {ip} (HTTP {r.status_code})")

    return save_jsonl(results, "shodan")


def collect_abuseipdb():
    """Collect blacklisted IPs from AbuseIPDB"""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()

    results = []
    for entry in data.get("data", []):
        results.append({
            "ip": entry.get("ipAddress", ""),
            "abuseConfidenceScore": entry.get("abuseConfidenceScore", 0),
            "countryCode": entry.get("countryCode", ""),
            "lastReportedAt": entry.get("lastReportedAt", ""),
            "source": "abuseipdb"
        })
    return save_jsonl(results, "abuseipdb")


def collect_greynoise():
    """Collect data from GreyNoise"""
    url = "https://api.greynoise.io/v3/community/quick/"
    ips = ["8.8.8.8", "1.1.1.1"]
    headers = {"Accept": "application/json", "key": GREYNOISE_API_KEY}
    results = []

    for ip in ips:
        r = requests.get(url + ip, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            data["source"] = "greynoise"
            results.append(data)
        else:
            print(f"⚠️ Skipped {ip} (HTTP {r.status_code})")

    return save_jsonl(results, "greynoise")


def collect_spamhaus():
    """Collect IP ranges from Spamhaus DROP and eDROP lists"""
    urls = [
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt",
        "https://www.spamhaus.org/drop/dropv6.txt",
    ]

    results = []
    for url in urls:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                parts = line.split(";")
                ip_range = parts[0].strip()
                desc = parts[1].strip() if len(parts) > 1 else ""
                results.append({
                    "ip": ip_range,
                    "description": desc,
                    "source": "spamhaus"
                })
        else:
            print(f"⚠️ Failed to fetch {url} ({r.status_code})")

    return save_jsonl(results, "spamhaus")


def collect_abusech():
    """Collect data from Abuse.ch URLHaus"""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    # No API key needed for this endpoint
    r = requests.post(url, timeout=30)
    r.raise_for_status()
    data = r.json()

    results = []
    for entry in data.get("urls", []):
        results.append({
            "url": entry.get("url", ""),
            "threat": entry.get("threat", ""),
            "date_added": entry.get("date_added", ""),
            "source": "abusech"
        })
    return save_jsonl(results, "abusech")


def collect_hybrid_analysis():
    """Collect recent reports from Hybrid Analysis"""
    url = "https://www.hybrid-analysis.com/api/v2/feed/latest"
    headers = {
        "api-key": HYBRID_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json"
    }

    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()

    try:
        data = r.json()
    except Exception:
        print("⚠️ Hybrid Analysis returned non-JSON response")
        return save_jsonl([], "hybrid_analysis")

    if not isinstance(data, list):
        print("⚠️ Unexpected Hybrid Analysis response format")
        return save_jsonl([], "hybrid_analysis")

    results = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        results.append({
            "sha256": entry.get("sha256", ""),
            "verdict": entry.get("verdict", ""),
            "threat_score": entry.get("threat_score", ""),
            "environment": entry.get("environment_description", ""),
            "source": "hybrid_analysis"
        })
    return save_jsonl(results, "hybrid_analysis")


def collect_virustotal():
    """Collect test data from VirusTotal"""
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file
    url = f"https://www.virustotal.com/api/v3/files/{test_hash}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        print("⚠️ VirusTotal request failed:", r.status_code)
        return save_jsonl([], "virustotal")

    data = r.json()
    item = data.get("data", {})
    results = [{
        "id": item.get("id", test_hash),
        "type": item.get("type", "file"),
        "links": item.get("links", {}),
        "source": "virustotal"
    }]
    return save_jsonl(results, "virustotal")


# ========================
# Main runner
# ========================

def run():
    sources = {
        "otx": collect_otx,
        "shodan": collect_shodan,
        "abuseipdb": collect_abuseipdb,
        "greynoise": collect_greynoise,
        "spamhaus": collect_spamhaus,
        "abusech": collect_abusech,
        "hybrid_analysis": collect_hybrid_analysis,
        "virustotal": collect_virustotal,
    }

    combined = []
    output_paths = {}

    for name, func in sources.items():
        print(f"\n🚀 Collecting data from {name}...")
        try:
            path = func()
            output_paths[name] = path
            print(f"✅ {name} data saved to {path}")

            with open(path, "rb") as f:
                for line in f:
                    try:
                        combined.append(json.loads(line))
                    except Exception:
                        continue

        except Exception as e:
            print(f"❌ Error collecting from {name}: {e}")

    combined_path = Path("data/combined")
    combined_path.mkdir(parents=True, exist_ok=True)
    final_file = combined_path / f"all_sources_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"

    with open(final_file, "wb") as f:
        f.write(json.dumps(combined))

    print(f"\n✅ Combined JSON saved to {final_file}")
    return final_file


if __name__ == "__main__":
    run()
