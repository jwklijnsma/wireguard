const $ = id => document.getElementById(id);
const labels = {disconnected:'Disconnected', connecting:'Connecting…', connected:'Connected', expired:'Session expired', error:'Not connected'};
let filled = false;

function bytes(n){const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i]}
function ago(t){if(!t||t.startsWith('0001'))return 'never';const s=Math.round((Date.now()-new Date(t))/1000);return s<60?s+'s ago':s<3600?Math.round(s/60)+'m ago':Math.round(s/3600)+'h ago'}
function left(t){const s=Math.round((new Date(t)-Date.now())/1000);if(s<=0)return 'expired';return Math.floor(s/3600)+'h '+String(Math.floor(s%3600/60)).padStart(2,'0')+'m left'}

async function api(path, body){
  const r = await fetch(path, {method: body===undefined?'GET':'POST', headers:{'Content-Type':'application/json','X-WG2FA':'1'}, body: body===undefined?undefined:JSON.stringify(body)});
  const j = await r.json().catch(()=>({error:r.statusText}));
  if(!r.ok) throw new Error(j.error||r.statusText);
  return j;
}

function render(s){
  $('card').className = 'card ' + s.state;
  $('stateText').textContent = labels[s.state] || s.state;
  $('ver').textContent = s.version; $('pub').textContent = (s.public_key||'').slice(0,12)+'…';
  const m = $('msg');
  if (s.message) { m.textContent = s.message; m.className = 'msg'; }
  else if (s.insecure && s.state !== 'connected') { m.textContent = 'Warning: server uses http://, your password and 2FA code are sent unencrypted.'; m.className = 'msg warn'; }
  else m.className = 'msg hidden';
  if (!filled) { $('server').value = s.server_url||''; $('username').value = s.username||''; $('device').value = s.device_name||''; filled = true; }
  const up = s.state === 'connected';
  $('login').classList.toggle('hidden', up || s.state==='connecting');
  $('info').classList.toggle('hidden', !up);
  if (up) {
    $('iProfile').textContent = s.profile||'-'; $('iAddr').textContent = s.address; $('iEndpoint').textContent = s.endpoint;
    $('iRoutes').textContent = (s.routes||[]).join(', '); $('iDNS').textContent = (s.dns||[]).join(', ')||'-';
    $('iExp').textContent = left(s.expires_at); $('iHs').textContent = ago(s.handshake);
    $('iTraffic').textContent = '↓ '+bytes(s.rx)+'  ↑ '+bytes(s.tx);
  }
  if (!$('username').value) $('username').focus(); else if (!up) $('totp').focus();
}

async function refresh(){ try { render(await api('/api/status')); } catch(e) {} }

$('login').addEventListener('submit', async e => {
  e.preventDefault();
  const b = $('connectBtn'); b.disabled = true; b.textContent = 'Connecting…';
  try {
    render(await api('/api/connect', {server_url:$('server').value, username:$('username').value, password:$('password').value, totp:$('totp').value, device_name:$('device').value}));
    $('password').value = '';
  } catch (err) { await refresh(); const m=$('msg'); m.textContent = err.message; m.className='msg'; }
  $('totp').value = ''; b.disabled = false; b.textContent = 'Connect';
});
$('disconnectBtn').addEventListener('click', async () => { render(await api('/api/disconnect', {})); });
refresh(); setInterval(refresh, 3000);
