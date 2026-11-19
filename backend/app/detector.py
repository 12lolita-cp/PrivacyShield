"""Conservative, explainable PII finding and redaction helpers.
False positives and OCR omissions are possible. Always review output manually.
"""
import io
import re
import os
from collections import defaultdict
import numpy as np
import cv2
import fitz
import pytesseract
from PIL import Image, ImageDraw

if os.getenv('TESSERACT_CMD'):
    pytesseract.pytesseract.tesseract_cmd = os.getenv('TESSERACT_CMD')

PATTERNS = {
    'Date of birth (possible)': re.compile(r'\b(?:date of birth|d\.?o\.?b\.?|birth date)\s*[:#-]?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b', re.I),
    'Email': re.compile(r'(?<![\w.])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?!\w)', re.I),
    'Phone': re.compile(r'(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,5}[\s.-]?\d{4}(?!\d)'),
    'Payment card (possible)': re.compile(r'(?<!\d)(?:\d[ -]?){13,19}(?!\d)'),
    'IBAN (possible)': re.compile(r'\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b', re.I),
    'Identification number (possible)': re.compile(r'\b(?:passport|aadhaar|aadhar|ssn|national id|account no\.?|account number|pan no\.?)\s*[:#-]?\s*[A-Z0-9-]{6,20}\b', re.I),
    'Address (possible)': re.compile(r'\b\d{1,5}\s+(?:[A-Za-z0-9]+\s+){1,6}(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|apartment|apt|blvd)\b', re.I),
}

def sensitive_matches(text):
    matches = []
    for label, pattern in PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group().strip()
            if label == 'Phone' and len(re.sub(r'\D', '', value)) < 9:
                continue
            if label.startswith('Payment') and not _luhn(re.sub(r'\D', '', value)):
                continue
            matches.append({'type': label, 'start': m.start(), 'end': m.end(), 'preview': _mask_preview(value)})
    # de-duplicate overlaps: favor a longer detection
    matches.sort(key=lambda f: (f['start'], -(f['end'] - f['start'])))
    chosen = []
    for m in matches:
        if not any(m['start'] < x['end'] and m['end'] > x['start'] for x in chosen):
            chosen.append(m)
    return chosen

def _luhn(s):
    if not s.isdigit() or not 13 <= len(s) <= 19:
        return False
    digits = list(map(int, s[::-1]))
    return sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d for i, d in enumerate(digits)) % 10 == 0

def _mask_preview(value):
    return (value[:2] + '•' * min(max(len(value)-4, 2), 12) + value[-2:]) if len(value) > 4 else '••••'

def _summary(items):
    counts = defaultdict(int)
    for item in items:
        counts[item['type']] += 1
    return [{'type': name, 'count': n} for name, n in counts.items()]

def _redact_text(s, matches):
    for f in reversed(matches):
        s = s[:f['start']] + '[REDACTED]' + s[f['end']:]
    return s

def process_text(payload, redact_types=None):
    text = payload.decode('utf-8', errors='replace')
    matches = sensitive_matches(text)
    to_redact = [m for m in matches if redact_types is None or m['type'] in redact_types]
    return matches, _redact_text(text, to_redact).encode('utf-8'), 'text/plain', 'redacted.txt', len(matches)

def _ocr_rects(image):
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    lines = defaultdict(list)
    for i, word in enumerate(data['text']):
        if not word.strip():
            continue
        key = (data['block_num'][i], data['par_num'][i], data['line_num'][i])
        lines[key].append((word, (data['left'][i], data['top'][i], data['left'][i] + data['width'][i], data['top'][i] + data['height'][i])))
    found = []
    rects = []
    for entries in lines.values():
        full = ''
        positions = []
        for word, rect in entries:
            if full:
                full += ' '
            start = len(full)
            full += word
            positions.append((start, len(full), rect))
        for hit in sensitive_matches(full):
            intersecting = [r for s, e, r in positions if s < hit['end'] and e > hit['start']]
            if intersecting:
                x0 = min(r[0] for r in intersecting)
                y0 = min(r[1] for r in intersecting)
                x1 = max(r[2] for r in intersecting)
                y1 = max(r[3] for r in intersecting)
                rects.append((x0, y0, x1, y1))
                found.append(hit)
    return found, rects

def process_image(payload, redact_types=None):
    im = Image.open(io.BytesIO(payload)).convert('RGB')
    if im.width * im.height > 20_000_000:
        raise ValueError('Image too large (20 megapixels maximum)')
    found, rects = _ocr_rects(im)
    chosen_rects = [rect for hit, rect in zip(found, rects) if redact_types is None or hit['type'] in redact_types]
    # A QR code can contain any type of data; redact all detected QR blocks.
    arr = cv2.cvtColor(np.array(im), cv2.COLOR_RGB2BGR)
    qr = cv2.QRCodeDetector()
    try:
        _, points, _ = qr.detectAndDecode(arr)
        if points is not None:
            xy = points.reshape(-1, 2)
            if redact_types is None or 'QR code' in redact_types:
                chosen_rects.append((int(np.min(xy[:,0])), int(np.min(xy[:,1])), int(np.max(xy[:,0])), int(np.max(xy[:,1]))))
            found.append({'type': 'QR code', 'preview': 'Content hidden'})
    except cv2.error:
        pass
    draw = ImageDraw.Draw(im)
    for x0, y0, x1, y1 in chosen_rects:
        draw.rectangle([max(0,x0-4), max(0,y0-4), min(im.width,x1+4), min(im.height,y1+4)], fill='black')
    out = io.BytesIO()
    im.save(out, format='PNG')
    return found, out.getvalue(), 'image/png', 'redacted.png', len(found)

def process_pdf(payload, redact_types=None):
    pdf = fitz.open(stream=payload, filetype='pdf')
    if pdf.page_count > 15:
        raise ValueError('PDF must have 15 pages or fewer')
    findings = []
    for page in pdf:
        if page.get_pixmap(matrix=fitz.Matrix(1,1)).width * page.get_pixmap(matrix=fitz.Matrix(1,1)).height > 20_000_000:
            raise ValueError('PDF page too large')
        lines = defaultdict(list)
        for w in page.get_text('words'):
            x0,y0,x1,y1,word,block,line,idx = w[:8]
            lines[(block,line)].append((word, fitz.Rect(x0,y0,x1,y1)))
        found_rects = []
        for entries in lines.values():
            full = ''
            offsets = []
            for word,rect in entries:
                if full: full += ' '
                st = len(full)
                full += word
                offsets.append((st,len(full),rect))
            for hit in sensitive_matches(full):
                overlapping = [rect for a,b,rect in offsets if a < hit['end'] and b > hit['start']]
                if overlapping:
                    r = overlapping[0]
                    for rr in overlapping[1:]: r |= rr
                    if redact_types is None or hit['type'] in redact_types:
                        found_rects.append(r)
                    findings.append(hit)
        # Also scan image-only PDFs through OCR and convert image-space positions to page coordinates.
        if not lines:
            pix = page.get_pixmap(matrix=fitz.Matrix(2,2), alpha=False)
            image = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
            hits, rects = _ocr_rects(image)
            findings.extend(hits)
            for hit, (x0,y0,x1,y1) in zip(hits, rects):
                if redact_types is None or hit['type'] in redact_types:
                    found_rects.append(fitz.Rect(x0/2,y0/2,x1/2,y1/2))
        for rect in found_rects:
            page.add_redact_annot(rect + (-1,-1,1,1), fill=(0,0,0))
        if found_rects:
            page.apply_redactions()
    data = pdf.tobytes(garbage=4, deflate=True)
    pdf.close()
    return findings, data, 'application/pdf', 'redacted.pdf', len(findings)
