from pathlib import Path

def test_breach_feature_removed():
    root = Path(__file__).resolve().parents[2]
    url_page = (root / 'frontend/src/pages/URLAnalyzer.jsx').read_text()
    api = (root / 'backend/app/main.py').read_text()
    assert 'Check your email for known breaches' not in url_page
    assert '/breach/email' not in url_page
    assert '/api/breach/email' not in api
    assert 'DNS lookup' in url_page and 'Live redirects' in url_page
