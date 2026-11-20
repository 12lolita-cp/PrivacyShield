const BASE = '/api';
export function getToken(){return localStorage.getItem('privacyshield_token')}
export async function api(endpoint, options={}) {
  const token = getToken();
  const headers = {...(options.body instanceof FormData ? {} : {'Content-Type':'application/json'}), ...(token ? {Authorization:`Bearer ${token}`} : {}), ...(options.headers||{})};
  let res;
  try {res = await fetch(BASE+endpoint, {...options, headers});}
  catch {throw new Error('Cannot connect to backend. Start FastAPI on port 8000.');}
  const data = await res.json().catch(()=>({}));
  if (!res.ok) {if(res.status===401 && !endpoint.startsWith('/auth/')) {localStorage.removeItem('privacyshield_token');window.location.href='/login';} throw new Error(typeof data.detail === 'string' ? data.detail : `Request failed (${res.status})`);}
  return data;
}
export function downloadBase64(encoded, mime, filename){
  const binary=atob(encoded);const bytes=new Uint8Array(binary.length);for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);
  const url=URL.createObjectURL(new Blob([bytes],{type:mime}));const a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),3000);
}
