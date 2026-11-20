import os
import json
import base64
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[1] / '.env')

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from . import storage
from .security import current_user, create_token, password_hash, verify_password, new_id
from .detector import process_image, process_pdf, process_text
from .threat_engine import assess_live_url
from .risk_engine import assess, CONTEXTS, WEIGHTS
from .intelligence import classify
from .media_tools import qr_report
from collections import Counter as FindingsCounter

@asynccontextmanager
async def lifespan(app):
    storage.init()
    yield

app = FastAPI(title='PrivacyShield API', version='4.0.0', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[s.strip() for s in os.getenv('FRONTEND_ORIGIN', 'http://localhost:5173').split(',')], allow_credentials=True, allow_methods=['GET','POST','DELETE'], allow_headers=['Authorization','Content-Type'])

class Register(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class Login(BaseModel):
    email: EmailStr
    password: str

class URLInput(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

class Exposure(BaseModel):
    service: str = Field(min_length=2, max_length=100)
    categories: list[str] = Field(min_length=1, max_length=12)
    notes: str = Field(default='', max_length=500)

CATEGORIES = {'Email address','Phone number','Home address','Date of birth','Location','Government ID','Payment information','Photos','Contacts','Other'}

@app.get('/api/health')
def health():
    return {'status': 'ok'}

@app.post('/api/auth/register')
def register(payload: Register):
    if storage.one_user(str(payload.email)):
        raise HTTPException(409, 'This email is already registered')
    user = {'id': new_id(), 'name': payload.name.strip(), 'email': str(payload.email).lower(), 'password_hash': password_hash(payload.password)}
    try: storage.create_user(user)
    except Exception: raise HTTPException(409, 'Unable to register this account')
    return {'token': create_token(user), 'user': {'name': user['name'], 'email': user['email']}}

@app.post('/api/auth/login')
def login(payload: Login):
    user = storage.one_user(str(payload.email))
    if not user or not verify_password(payload.password, user['password_hash']):
        raise HTTPException(401, 'Incorrect email or password')
    return {'token': create_token(user), 'user': {'name': user['name'], 'email': user['email']}}

@app.get('/api/me')
def me(user=Depends(current_user)):
    return {'name': user['name'], 'email': user['email']}

@app.post('/api/scan')
async def scan(file: UploadFile = File(...), sharing_context: str = Form('public'), redact_types: str = Form('all'), user=Depends(current_user)):
    if sharing_context not in CONTEXTS:
        raise HTTPException(400, 'Invalid sharing context')
    try:
        chosen_types = None if redact_types == 'all' else set(json.loads(redact_types))
        if chosen_types is not None and (not isinstance(json.loads(redact_types), list) or not chosen_types.issubset(WEIGHTS)):
            raise ValueError()
    except (ValueError, TypeError):
        raise HTTPException(400, 'Invalid redaction selection')
    raw = await file.read(10 * 1024 * 1024 + 1)
    await file.close()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(413, 'Maximum file size is 10 MB')
    name = Path(file.filename or 'upload').name
    ext = Path(name).suffix.lower()
    try:
        if ext in ('.png','.jpg','.jpeg','.webp'):
            from PIL import Image
            import io
            Image.open(io.BytesIO(raw)).verify()
            result = process_image(raw, chosen_types)
        elif ext == '.pdf':
            if not raw.startswith(b'%PDF'):
                raise ValueError('Invalid PDF file')
            result = process_pdf(raw, chosen_types)
        elif ext == '.txt':
            result = process_text(raw, chosen_types)
        else:
            raise ValueError('Supported types: PNG, JPG, WEBP, PDF and TXT')
    except Exception as exc:
        raise HTTPException(400, f'Could not scan file: {exc}') from exc
    detected, data, mime, outname, count = result
    try:
        if ext == '.txt':
            source_text = raw.decode('utf-8', errors='replace')
        elif ext == '.pdf':
            import fitz
            from PIL import Image
            import pytesseract, io
            with fitz.open(stream=raw, filetype='pdf') as doc:
                snippets=[]
                for page in doc:
                    content=page.get_text()
                    if not content.strip():
                        pix=page.get_pixmap(matrix=fitz.Matrix(1.5,1.5))
                        content=pytesseract.image_to_string(Image.open(io.BytesIO(pix.tobytes('png'))))
                    snippets.append(content)
                source_text=' '.join(snippets)
        else:
            from PIL import Image
            import pytesseract, io
            source_text=pytesseract.image_to_string(Image.open(io.BytesIO(raw)))
        classification=classify(source_text)
    except Exception:
        classification=classify('')
    findings_counter = FindingsCounter(hit['type'] for hit in detected)
    findings = [{'type': typ, 'count': n} for typ, n in findings_counter.items()]
    assessment = assess(detected, sharing_context)
    storage.insert('scans', {'id': new_id(), 'user_id': user['id'], 'filename': name, 'risk': assessment['score'], 'findings': json.dumps(findings)})
    return {'filename': outname, 'mime': mime, 'file_base64': base64.b64encode(data).decode(), 'findings': findings,
            'count': count, 'risk': assessment['score'], 'assessment': assessment, 'classification': classification,
            'redacted_types': sorted(chosen_types if chosen_types is not None else findings_counter.keys()),
            'notice': 'Automated detection may miss sensitive information, particularly in scanned or complex PDFs. Review every page before sharing. Unselected categories remain visible.'}

@app.post('/api/qr/analyze')
async def qr_analyze(file: UploadFile = File(...), user=Depends(current_user)):
    raw = await file.read(10 * 1024 * 1024 + 1)
    await file.close()
    if len(raw) > 10 * 1024 * 1024: raise HTTPException(413, 'Maximum file size is 10MB')
    if Path(file.filename or '').suffix.lower() not in ('.png','.jpg','.jpeg','.webp'):
        raise HTTPException(400, 'Upload PNG, JPG, or WEBP image')
    try: return qr_report(raw, analyzer=assess_live_url)
    except Exception as exc: raise HTTPException(400, f'QR analysis failed: {exc}') from exc



@app.get('/api/footprint/insights')
def footprint_insights(user=Depends(current_user)):
    rows = storage.list_for('exposures', user['id'])
    category_counts = Counter(cat for item in rows for cat in json.loads(item['categories']))
    high_sensitivity = {'Government ID','Payment information','Home address','Date of birth','Location'}
    exposure_points = sum(min(4,n)*(18 if category in high_sensitivity else 7) for category,n in category_counts.items())
    score=min(100, exposure_points)
    actions=[]
    for category,n in category_counts.most_common():
        if category in high_sensitivity:
            actions.append(f'{category} recorded with {n} service(s): review whether each service still needs it.')
        elif n >= 3:
            actions.append(f'{category} recorded with {n} services: review permissions and retention settings.')
    if not actions: actions.append('Record services and shared categories to generate personalized guidance.')
    edges=[{'service':r['service'],'category':cat} for r in rows[:30] for cat in json.loads(r['categories'])]
    return {'score':score,'level':'High' if score>=70 else 'Moderate' if score>=30 else 'Low',
            'categories':[{'name':k,'count':v} for k,v in category_counts.most_common()],
            'services':len(rows),'connections':edges[:100], 'recommendations':actions[:8],
            'method':'Self-reported information-sharing categories weighted by sensitivity and frequency. This is not a measured online breach or discovery of leaked data.'}

@app.post('/api/url/analyze')
def url_check(payload: URLInput, user=Depends(current_user)):
    try: result = assess_live_url(payload.url)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    storage.insert('urls', {'id': new_id(), 'user_id': user['id'], 'url': result['url'], 'score': result['score'], 'level': result['level'], 'reasons': json.dumps(result['reasons'])})
    return result

@app.get('/api/exposures')
def exposures(user=Depends(current_user)):
    rows = storage.list_for('exposures', user['id'])
    for row in rows: row['categories'] = json.loads(row['categories'])
    return rows

@app.post('/api/exposures')
def add_exposure(payload: Exposure, user=Depends(current_user)):
    if not set(payload.categories).issubset(CATEGORIES): raise HTTPException(400, 'Invalid data category')
    obj = storage.insert('exposures', {'id': new_id(), 'user_id': user['id'], 'service': payload.service.strip(), 'categories': json.dumps(sorted(set(payload.categories))), 'notes': payload.notes.strip()})
    obj['categories'] = json.loads(obj['categories'])
    return obj

@app.delete('/api/exposures/{item_id}')
def remove_exposure(item_id: str, user=Depends(current_user)):
    if not storage.delete_exposure(item_id, user['id']): raise HTTPException(404, 'Record not found')
    return {'ok': True}

@app.get('/api/dashboard')
def dashboard(user=Depends(current_user)):
    scans = storage.list_for('scans', user['id'])
    urls = storage.list_for('urls', user['id'])
    exposures = storage.list_for('exposures', user['id'])
    category_counts = Counter(cat for e in exposures for cat in json.loads(e['categories']))
    recommendations = []
    if category_counts.get('Government ID') or category_counts.get('Payment information'):
        recommendations.append('Review services that have your ID or payment details; remove unnecessary copies.')
    if category_counts.get('Location') or category_counts.get('Home address'):
        recommendations.append('Limit precise location and address sharing to services that truly need it.')
    if len(exposures) >= 5:
        recommendations.append('Audit older accounts and delete unused profiles or revoke unnecessary permissions.')
    if any(u['score'] >= 30 for u in urls):
        recommendations.append('Verify the domain independently before visiting or entering information into suspicious links.')
    recommendations += ['Enable multifactor authentication on important accounts.', 'Check privacy settings and review account permissions regularly.', 'Review masked files manually before sending them.']
    return {'counts': {'scans': len(scans), 'urls': len(urls), 'services': len(exposures), 'flagged_urls': sum(x['score'] >= 30 for x in urls)},
            'categories': [{'name': k, 'count': v} for k,v in category_counts.most_common()],
            'scans': scans[:5], 'urls': urls[:5], 'recommendations': recommendations[:6]}
