"""Transparent context-based exposure heuristics, not a breach or fraud prediction."""
from collections import Counter

WEIGHTS = {
    'Email': 10,
    'Phone': 14,
    'Address (possible)': 22,
    'Identification number (possible)': 28,
    'Payment card (possible)': 30,
    'IBAN (possible)': 30,
    'Date of birth (possible)': 20,
    'QR code': 13,
}
EXPLANATIONS = {
    'Email': ('Email exposure', 'Can be used for unwanted contact or targeted phishing.', 'Share only when contact by email is necessary.'),
    'Phone': ('Phone number exposure', 'May enable unsolicited calls, messaging scams, or targeted impersonation.', 'Remove phone numbers when recipients do not need to call you.'),
    'Address (possible)': ('Physical location exposure', 'A full street address can disclose private location information.', 'Hide street and apartment information from public copies.'),
    'Identification number (possible)': ('Identity document exposure', 'Account and identity identifiers may be misused when combined with other data.', 'Avoid sharing complete ID or account numbers unless required by a trusted recipient.'),
    'Payment card (possible)': ('Payment detail exposure', 'Card numbers are highly sensitive and should not appear in public documents.', 'Redact the complete number; keep only an approved last-four-digits view if needed.'),
    'IBAN (possible)': ('Banking detail exposure', 'Account identifiers should only be given to a trusted intended party.', 'Remove bank identifiers from publicly shared files.'),
    'Date of birth (possible)': ('Birth date exposure', 'A birth date can strengthen identity-based impersonation when combined with other details.', 'Hide full birth dates where age confirmation is not required.'),
    'QR code': ('QR code disclosure', 'QR codes may embed links or personal information; contents have not been verified.', 'Check QR contents separately before sharing.'),
}
CONTEXTS = {
    'public': ('Public post / social media', 1.4),
    'unknown': ('Unknown recipient', 1.25),
    'work': ('Work or college submission', 1.05),
    'trusted': ('Trusted private recipient', 0.8),
}

def assess(findings, context='public'):
    if context not in CONTEXTS:
        context = 'public'
    counts = Counter(f['type'] for f in findings)
    types = set(counts)
    base = sum(min(counts[t], 3) * weight for t, weight in WEIGHTS.items() if t in counts)
    combinations = []
    if 'Email' in types and 'Phone' in types:
        base += 12
        combinations.append('Email + phone can make impersonation messages more convincing.')
    if 'Address (possible)' in types and ('Phone' in types or 'Email' in types):
        base += 15
        combinations.append('Address combined with contact details increases personal exposure.')
    if 'Date of birth (possible)' in types and 'Identification number (possible)' in types:
        base += 18
        combinations.append('Birth date plus an identity number can support identity-based impersonation.')
    if ('Payment card (possible)' in types or 'IBAN (possible)' in types) and ('Email' in types or 'Phone' in types):
        base += 12
        combinations.append('Financial and contact information together merit additional protection.')
    name, multiplier = CONTEXTS[context]
    score = min(100, round(base * multiplier))
    level = 'High' if score >= 70 else ('Moderate' if score >= 30 else 'Low')
    explanations = [
        {'type': typ, 'count': counts[typ], 'severity': 'High' if WEIGHTS.get(typ, 0) >= 20 else 'Moderate',
         'title': EXPLANATIONS[typ][0], 'why': EXPLANATIONS[typ][1], 'action': EXPLANATIONS[typ][2]}
        for typ in sorted(types, key=lambda t: -WEIGHTS.get(t, 0)) if typ in EXPLANATIONS
    ]
    if not findings:
        verdict = 'No recognized patterns found. This does not mean the document is safe.'
    elif level == 'High':
        verdict = 'Avoid sharing this file as-is. Review sensitive details and redact unnecessary identifiers.'
    elif level == 'Moderate':
        verdict = 'Review the highlighted categories before sharing this file.'
    else:
        verdict = 'Some personal information was found. Review it before sharing.'
    suggestions = [i['action'] for i in explanations]
    if context == 'public' and findings:
        suggestions.insert(0, 'For a public post, remove all identifiers that are not essential.')
    return {
        'score': score, 'level': level, 'context': context, 'context_label': name,
        'verdict': verdict, 'explanations': explanations, 'combinations': combinations,
        'recommendations': list(dict.fromkeys(suggestions))[:7],
        'score_method': 'Illustrative heuristic: category weights, frequency (capped at three), combination bonuses, and sharing-context multiplier. Not a probability of harm.',
    }
