"""QR decoding; images are not saved or sent to external sites."""
import io
import ipaddress
from urllib.parse import urlsplit
import cv2
import numpy as np
from PIL import Image
from .urlcheck import analyze_url


def _image(raw):
    im = Image.open(io.BytesIO(raw))
    if im.width * im.height > 20_000_000: raise ValueError('Image exceeds 20 megapixels')
    im.verify()
    return Image.open(io.BytesIO(raw))

def _decode_qr_variants(rgb):
    """Try QR detection on source image and lightly enhanced variants."""
    detector = cv2.QRCodeDetector()
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    candidates = [gray]
    height, width = gray.shape
    if min(height, width) < 900:
        scale = min(3, 1200 / max(height, width))
        if scale > 1.01:
            candidates.append(cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC))
    candidates.append(cv2.equalizeHist(gray))
    _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(binary)
    # Rotated photos are common; adaptive binarization can improve lower-contrast scans.
    candidates.append(cv2.adaptiveThreshold(gray,255,cv2.ADAPTIVE_THRESH_GAUSSIAN_C,cv2.THRESH_BINARY,31,8))
    for turns in (1,2,3):
        candidates.append(np.rot90(gray,turns).copy())
    results = []
    for candidate in candidates:
        try:
            ok, decoded, _, _ = detector.detectAndDecodeMulti(candidate)
            if ok:
                results.extend(x for x in decoded if x)
            if not results:
                value, _, _ = detector.detectAndDecode(candidate)
                if value:
                    results.append(value)
        except cv2.error:
            continue
        if results:
            break
    return list(dict.fromkeys(results))[:10]


def qr_report(raw, analyzer=None):
    image = _image(raw).convert('RGB')
    array = np.array(image)
    contents = _decode_qr_variants(array)
    results = []
    for text in contents:
        is_url = text.lower().startswith(('http://','https://')) or ('.' in text and ' ' not in text and not text.lower().startswith(('mailto:','upi:','wifi:','begin:vcard','otpauth:'))) 
        if is_url:
            try:
                risk = analyzer(text) if analyzer else analyze_url(text)
                results.append({'kind':'URL','preview':text[:120], 'risk':risk})
            except ValueError:
                results.append({'kind':'Unrecognized URL','preview':text[:100], 'risk':None})
        else:
            lowered = text.lower()
            may_be_sensitive = any(term in lowered for term in ('upi://','mailto:','tel:','wifi:','begin:vcard','otpauth:'))
            results.append({'kind':'Potential personal/payment data' if may_be_sensitive else 'Other text', 'preview':'Content concealed for privacy' if may_be_sensitive else text[:90], 'length':len(text), 'risk':None})
    return {
        'count':len(results),
        'items':results,
        'warning': None if results else 'No readable QR code was detected. Try the original PNG/JPG image rather than a screenshot, crop around the full QR code, and ensure all four corners and the white border are visible.',
        'notice':'QR contents were decoded from the uploaded image. URL results include live public DNS and guarded redirect checks where available. Payment recipients should always be independently verified.'
    }

