"""Explainable structural URL risk indicator (used alongside independent live network checks)."""
import re
import ipaddress
import unicodedata
from urllib.parse import urlsplit, unquote

SHORTENERS = {'bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rebrand.ly','ow.ly','shorturl.at','tiny.cc'}
KNOWN_BRANDS = {'paypal':'paypal.com','google':'google.com','microsoft':'microsoft.com','apple':'apple.com','amazon':'amazon.com','instagram':'instagram.com','facebook':'facebook.com','netflix':'netflix.com'}
RISK_TLDS = {'.zip','.top','.click','.xyz','.work'}

def analyze_url(raw):
    raw = raw.strip()
    if not 4 <= len(raw) <= 2048: raise ValueError('URL must be 4–2048 characters')
    candidate = raw if '://' in raw else 'https://' + raw
    try:
        p = urlsplit(candidate)
        if p.scheme not in ('http','https'): raise ValueError()
        host = (p.hostname or '').strip('.').lower()
        if not host: raise ValueError()
        if any(c.isspace() for c in host): raise ValueError()
        host_ascii = host.encode('idna').decode('ascii')
        _ = p.port
        is_ip = False
        try: ipaddress.ip_address(host_ascii.strip('[]')); is_ip = True
        except ValueError: pass
        if not is_ip and (not re.fullmatch(r'[a-z0-9.-]+',host_ascii) or '.' not in host_ascii or '..' in host_ascii): raise ValueError()
    except (ValueError,UnicodeError,AttributeError) as exc:
        raise ValueError('Enter a valid HTTP or HTTPS URL with a public hostname') from exc
    flags=[]; score=0
    def flag(points, message, code):
        nonlocal score
        score+=points;flags.append({'points':points,'message':message,'code':code})
    if p.scheme=='http': flag(20,'HTTP does not encrypt data in transit.','http')
    if host_ascii in SHORTENERS: flag(30,'Shortened URLs hide the final destination.','shortener')
    if is_ip: flag(25,'Direct IP-address links deserve additional verification.','ip')
    if p.username or p.password: flag(35,'Userinfo before @ can disguise the true destination.','userinfo')
    if len(candidate)>100: flag(10,'Unusually long URL.','length')
    if host_ascii.count('.')>=3: flag(12,'Many subdomains can make the real domain difficult to spot.','subdomains')
    if host_ascii.count('-')>=3: flag(12,'Multiple hyphens in the hostname.','hyphens')
    if host_ascii.endswith(tuple(RISK_TLDS)): flag(8,'This top-level domain warrants additional caution; it is not automatically malicious.','tld')
    if re.search(r'(login|verify|urgent|secure|account|update|reset|signin|confirm|password)',unquote(p.path+'?'+p.query),re.I): flag(12,'Account or urgency terms appear in the link path.','keywords')
    if re.search(r'%[0-9a-f]{2}',candidate,re.I): flag(8,'URL-encoded characters can obscure readable paths.','encoding')
    if 'xn--' in host_ascii: flag(18,'Internationalized/punycode hostname: check for lookalike letters.','punycode')
    if any(ord(c)>127 for c in host): flag(14,'Unicode hostname: visually similar characters may be misleading.','unicode')
    for brand,official in KNOWN_BRANDS.items():
        if brand in host_ascii and host_ascii!=official and not host_ascii.endswith('.'+official):
            flag(24,f'Hostname mentions {brand} but is not its usual {official} domain. Verify independently.','brand_lookalike')
            break
    if not flags: flags=[{'points':0,'message':'No listed warning patterns found. This does not certify the site as safe.','code':'none'}]
    score=min(100,score)
    return {'url':candidate,'host':host,'score':score,'level':'High' if score>=60 else 'Moderate' if score>=30 else 'Low','reasons':flags,'disclaimer':'Structural scoring alone cannot establish whether a link is safe.','checks_performed':['HTTPS scheme','shorteners','IP addresses','userinfo tricks','length','subdomains','hyphens','URL encoding','urgency words','punycode','brand lookalikes']}
