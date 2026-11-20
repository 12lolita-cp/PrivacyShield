"""Assess arbitrary public URLs using explainable heuristics and two live network checks.
Only live DNS resolution and guarded HTTP(S) redirects are performed.
"""
from urllib.parse import urlsplit
from .urlcheck import analyze_url
from .live_checks import dns_lookup, redirect_chain


def assess_live_url(url, inspect_redirects=True):
    base = analyze_url(url)
    # Userinfo can disguise hostname and is not contacted by our network scanner.
    if '@' in urlsplit(base['url']).netloc:
        inspect_redirects = False
    dns = dns_lookup(base['host'])
    redirects = (redirect_chain(base['url']) if inspect_redirects and dns['status'] == 'completed'
                 else {'status': 'not_performed', 'chain': [],
                       'detail': 'Redirect check skipped: DNS unavailable or input is unsafe to probe'})
    final_url = redirects.get('final_url', base['url'])
    final_struct = analyze_url(final_url)
    score = max(base['score'], final_struct['score'])
    reasons = list(base['reasons'])
    if final_url != base['url']:
        reasons = [r for r in reasons if r.get('code') != 'none']
        reasons.append({'points': 0, 'code': 'redirect_observed',
                        'message': 'This URL redirects to another address; inspect the final destination independently.'})
        for r in final_struct['reasons']:
            if r.get('points', 0) > 0:
                reasons.append({'points': 0, 'code': 'destination_' + r['code'],
                                'message': 'At redirect destination: ' + r['message']})
    level = 'High' if score >= 60 else 'Moderate' if score >= 30 else 'Low' 
    checks_completed = sum(check.get('status') == 'completed' for check in (dns, redirects))
    verification_status = 'completed' if checks_completed == 2 else 'partial'
    if verification_status == 'completed':
        coverage = 'Both live checks completed. DNS and redirects do not guarantee safety.'
    else:
        coverage = 'Some live network checks could not complete. Structural warning patterns are shown separately.'
    return {**base,
            'score': score, 'level': level, 'heuristic_score': score,
            'final_url': final_url, 'reasons': reasons,
            'live_checks': {'dns': dns, 'redirects': redirects},
            'checks_completed': checks_completed, 'checks_available': 2,
            'verification_status': verification_status,
            'coverage_message': coverage,
            'evidence': ([{'type': 'redirect', 'message': 'A redirect was observed; review the destination.', 'source': 'Live redirect check'}]
                         if redirects.get('status') == 'completed' and final_url != base['url'] else []),
            'disclaimer': 'A low structural risk score does not guarantee safety. DNS and redirects cannot confirm that a URL is free from malware or phishing.',
            'scoring_method': '0–100 structural URL risk indicator based on explainable warning patterns. The higher of original and final redirect URL scores is used. This is not a calibrated probability or malware verdict.'}
