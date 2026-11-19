"""Explainable document classification and privacy context signals (not an LLM)."""
import re

DOCUMENTS = {
 'Resume / CV': {'resume','curriculum vitae','work experience','education','skills','professional summary','linkedin'},
 'Bank statement': {'bank statement','transaction date','account balance','closing balance','account holder','sort code','ifsc'},
 'Identity document': {'passport','national identity','aadhar','aadhaar','driving licence','date of birth','identity card'},
 'Academic document': {'student id','university','enrollment','admission','semester','transcript','marksheet'},
 'Invoice / receipt': {'invoice','receipt','total amount','bill to','invoice number','payment due'},
 'Medical document': {'patient','diagnosis','prescription','medical record','hospital','doctor'},
 'Account screenshot': {'sign in','login','profile','settings','two-factor','reset password'},
}
ADVICE = {
 'Resume / CV': 'For public job boards, consider withholding full street address, date of birth and ID numbers. Keep only contact details you intend recruiters to use.',
 'Bank statement': 'Only share with a verified recipient who requires it. Cover unrelated transactions, account identifiers and balances if not needed.',
 'Identity document': 'Identity documents are high sensitivity. Verify the recipient and requirement; redact identifiers only when the recipient permits.',
 'Academic document': 'Avoid publishing student IDs, birth dates and contact details alongside academic records.',
 'Invoice / receipt': 'Review billing addresses, account identifiers and QR payment links before sharing.',
 'Medical document': 'Health records are especially private. Share only necessary pages with authorized recipients.',
 'Account screenshot': 'Remove usernames, recovery details, visible tokens and account-specific settings before posting.',
 'General document': 'Scan results depend on text visibility and patterns. Check every page and image before sharing.',
}
def classify(text):
    normalized = re.sub(r'\s+', ' ', text.lower())[:200000]
    scores = {kind: sum(2 if len(keyword.split()) > 1 else 1 for keyword in phrases if keyword in normalized) for kind, phrases in DOCUMENTS.items()}
    kind, score = max(scores.items(), key=lambda item: item[1])
    if score < 2: kind = 'General document'
    return {'type': kind, 'confidence': 'strong cues' if score >= 5 else ('some cues' if score >= 2 else 'insufficient cues'), 'evidence': [word for word in DOCUMENTS.get(kind, ()) if word in normalized][:5], 'recommendation': ADVICE[kind], 'method': 'Transparent keyword classification; may misclassify short or scanned documents.'}
