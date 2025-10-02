import requests

def get(url: str, params: dict | None = None, headers: dict | None = None):
    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp
