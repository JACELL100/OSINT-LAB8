# Threat Intelligence Aggregation Platform

A comprehensive platform for collecting, normalizing, and visualizing threat intelligence from multiple sources.

## Features

- **Multi-Source Collection**: Gathers threat data from 8 different sources:
  - AlienVault OTX
  - Abuse.ch URLhaus
  - AbuseIPDB
  - GreyNoise
  - Hybrid Analysis
  - Shodan
  - Spamhaus DROP lists
  - VirusTotal

- **Data Normalization**: Converts raw threat data into standardized STIX format
- **Interactive Dashboard**: Web-based visualization of threat intelligence data
- **Export Capabilities**: Export merged data in JSONL format

## Requirements

- Python 3.x
- pip
- Virtual environment (recommended)

## Installation

1. Clone the repository:
git clone <repository-url>
cd threat-aggregation-lab-full


2. Create and activate virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:
pip install -r requirements.txt

Configuration
Add your API keys to the configuration file for each service you want to use:

OTX_API_KEY
SHODAN_API_KEY
ABUSEIPDB_API_KEY
GREYNOISE_API_KEY
HYBRID_API_KEY
VT_API_KEY

Usage

Collecting Data
Run individual collectors:
python -m src.collectors.collector

Normalizing Data
Convert raw data to STIX format:
python -m src.normalizers.normalizer <input-file>

Viewing Results
Open index.html in a web browser
Drag and drop your .jsonl or .stix.jsonl files onto the interface
Explore the visualizations and data analysis
Data Structure
data/raw/ - Raw data from each source
data/processed/ - Normalized STIX format data
data/combined/ - Merged data from all sources