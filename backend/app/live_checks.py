"""Bounded DNS/redirect checks. No page scripts, local-network requests, or reputation-provider calls."""
import os, socket, ipaddress
from urllib.parse import urlsplit, urljoin
import urllib3
import certifi

TIMEOUT = (2.5, 4)
UA = 'PrivacyShield/4.0 (HEAD-only threat assessment)'

def _public_addresses(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addrs = list(dict.fromkeys(x[4][0] for x in infos))
        if not addrs or any(not ipaddress.ip_address(a).is_global for a in addrs):
            return None, 'DNS lookup returned a private, special-use, or unresolvable address'
        return addrs, None
    except (OSError, ValueError) as e:
        return None, ("Domain did not resolve to a public address (DNS lookup failed). \"example.com\" and its subdomains are reserved for documentation; test real public domains for live checks." if host.lower().endswith('.example.com') or host.lower() == 'example.com' else f'DNS lookup failed: {type(e).__name__}. The domain may not exist, be unreachable, or have DNS problems.')

def dns_lookup(host):
    addrs, error = _public_addresses(host, 443)
    if error: return {'status':'error','detail':error,'addresses':[]}
    return {'status':'completed','addresses':addrs[:8],'detail':'Live public DNS resolution'}

def redirect_chain(url):
    """HEAD requests only; pin every connection to a previously validated public IP.
    Redirects are validated independently; no body or browser content is fetched.
    """
    chain=[]
    current=url
    for _ in range(5):
        p=urlsplit(current)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:
            return {'status':'blocked','chain':chain,'detail':'Invalid or unsafe redirect target'}
        port=p.port or (443 if p.scheme=='https' else 80)
        if port not in (80,443):
            return {'status':'blocked','chain':chain,'detail':'Only HTTP/HTTPS default ports may be contacted'}
        addresses, error=_public_addresses(p.hostname,port)
        if error: return {'status':'blocked','chain':chain,'detail':error}
        host=p.hostname
        path=(p.path or '/') + ('?' + p.query if p.query else '')
        try:
            kwargs={'host':addresses[0],'port':port,'timeout':urllib3.Timeout(connect=2.5,read=4), 'maxsize':1,'retries':False, 'cert_reqs':'CERT_REQUIRED', 'ca_certs':certifi.where()}
            if p.scheme=='https':
                pool=urllib3.HTTPSConnectionPool(server_hostname=host, assert_hostname=host,**kwargs)
            else: pool=urllib3.HTTPConnectionPool(**kwargs)
            with pool:
                headers={'Host':host, 'User-Agent':UA, 'Accept':'*/*'}
                response=pool.request('HEAD',path,headers=headers,redirect=False,preload_content=False)
                status=response.status
                location=response.headers.get('Location','')
                response.release_conn()
                # Some public websites disallow HEAD. GET is issued without reading
                # the response body; no scripts or downloaded content are executed.
                if status in (405,501):
                    response=pool.request('GET',path,headers={**headers,'Range':'bytes=0-0'},redirect=False,preload_content=False)
                    status=response.status
                    location=response.headers.get('Location','')
                    response.release_conn()
        except (urllib3.exceptions.SSLError, Exception) as exc:
            category=type(exc).__name__
            if 'SSL' in category or 'Certificate' in str(exc):
                detail='Could not verify the HTTPS certificate. Check your Mac CA certificates, system date, network proxy or the destination certificate.'
            else:
                detail=f'Connection could not be verified ({category}). The site was not classified safe.'
            return {'status':'unavailable','chain':chain,'detail':detail}
        chain.append({'url':current,'status_code':status,'ip':addresses[0]})
        if status not in (301,302,303,307,308) or not location:
            return {'status':'completed','chain':chain,'final_url':current,'detail':'Redirect inspection completed with verified TLS where applicable'}
        next_url=urljoin(current, location)
        if next_url in [a['url'] for a in chain]:
            return {'status':'blocked','chain':chain,'detail':'Redirect loop detected'}
        current=next_url
    return {'status':'limit','chain':chain,'detail':'Stopped after five redirect hops'}

