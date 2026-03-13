'use strict';
/* ═══════════════════════════════════════════════
   CONFIG
═══════════════════════════════════════════════ */
const API_BASE = '';  // same origin
let authToken  = null;
let feedCount  = 0;
let roomsBuilt = false;

/* ═══════════════════════════════════════════════
   CLOCK
═══════════════════════════════════════════════ */
setInterval(() => {
  const time = new Date().toLocaleTimeString("en-GB", {
    timeZone: "Asia/Phnom_Penh",
    hour12: false
  });
  document.getElementById("clock").textContent = time;
}, 1000);

/* ═══════════════════════════════════════════════
   API HELPER — real fetch to backend
═══════════════════════════════════════════════ */
async function api(path, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {})
  };
  try {
    const res = await fetch(API_BASE + path, {
      method:  opts.method || 'GET',
      headers,
      body:    opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: 'same-origin'
    });
    if (res.status === 429) { toast('Rate limited — slow down', 'red'); throw new Error('Rate limited'); }
    if (res.status === 401) { handleUnauth(); throw new Error('Unauthorized'); }
    if (res.status === 403) { toast('Access denied', 'red'); throw new Error('Forbidden'); }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  } catch(e) {
    if (e.message !== 'Rate limited' && e.message !== 'Unauthorized' && e.message !== 'Forbidden') {
      console.error(`API ${path}:`, e.message);
    }
    throw e;
  }
}

function handleUnauth() {
  authToken = null;
  document.getElementById('login-overlay').style.display = 'flex';
  toast('Session expired — please log in again', 'red');
}

/* ═══════════════════════════════════════════════
   LOGIN
═══════════════════════════════════════════════ */
async function doLogin() {
  const username  = document.getElementById('login-user').value.trim();
  const password  = document.getElementById('login-pass').value;
  const totp      = document.getElementById('login-totp').value.trim();
  const honeypot  = document.getElementById('hp-website').value;
  const errEl     = document.getElementById('login-error');
  const btn       = document.getElementById('login-btn');

  // Client-side honeypot check
  if (honeypot) {
    errEl.textContent = 'Forbidden';
    errEl.style.display = 'block';
    return;
  }

  if (!username || !password) {
    errEl.textContent = 'Username and password required';
    errEl.style.display = 'block';
    return;
  }

  errEl.style.display = 'none';
  btn.disabled = true;
  btn.textContent = 'AUTHENTICATING...';

  try {
    const totpVisible = document.getElementById('totp-field').style.display !== 'none';
    const body = { username, password, ...(totpVisible && totp ? { totp } : {}) };

    const data = await api('/api/auth/login', { method: 'POST', body });

    authToken = data.token;
    document.getElementById('login-overlay').style.display = 'none';
    addFeedEvent('info', 'AUTH_SUCCESS', `Login: ${username}`, '127.0.0.1');
    await loadDashboard();
    setInterval(loadDashboard, 30000);
    toast(`Welcome, ${data.user.username}!`, 'green');

  } catch(e) {
    if (e.message.includes('TOTP')) {
      document.getElementById('totp-field').style.display = 'block';
      errEl.textContent = e.message;
    } else {
      errEl.textContent = e.message || 'Authentication failed';
    }
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'AUTHENTICATE →';
  }
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const ov = document.getElementById('login-overlay');
    if (ov && ov.style.display !== 'none') doLogin();
  }
});

/* ═══════════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════════ */
async function loadDashboard() {
  try {
    const d = await api('/api/security/dashboard');

    set('h-threats',  d.threats.unresolved);
    set('h-blocked',  d.firewall_blocks);
    set('h-sessions', d.active_sessions);
    set('h-users',    d.user_count);
    set('s-threats',  d.threats.unresolved);
    set('s-blocked',  d.firewall_blocks);
    set('s-sessions', d.active_sessions);
    set('s-audit',    d.audit_count);
    set('nav-threat-count', d.threats.unresolved);

    const score = Math.min(d.threats.critical * 25 + d.threats.unresolved * 5, 100);
    const color = score > 70 ? 'var(--red)' : score > 40 ? 'var(--amber)' : 'var(--green)';
    const fill  = document.getElementById('threat-fill');
    fill.style.width = score + '%';
    fill.style.background = color;
    styleEl('threat-level-val', color);
    set('threat-level-val', score);
    set('threat-text', score > 70 ? 'CRITICAL' : score > 40 ? 'ELEVATED' : score > 10 ? 'GUARDED' : 'NOMINAL');

    const chart = document.getElementById('threat-chart');
    if (d.threat_by_type.length) {
      const max = Math.max(...d.threat_by_type.map(t => t.count));
      const clr = { suspicious_login:'var(--red)', port_scan:'var(--amber)', brute_force:'var(--red)', scanner_detected:'var(--green-dim)', xss_attempt:'var(--blue)', path_traversal:'var(--blue)', safety_device_disabled:'var(--red)' };
      chart.innerHTML = d.threat_by_type.map(t => `
        <div class="h-bar-row">
          <div class="h-bar-label">${t.event_type.replace(/_/g,' ')}</div>
          <div class="h-bar-track"><div class="h-bar-fill" style="width:${(t.count/max*100).toFixed(1)}%;background:${clr[t.event_type]||'var(--green)'};color:${clr[t.event_type]||'var(--green)'}"></div></div>
          <div class="h-bar-val">${t.count}</div>
        </div>`).join('');
    } else {
      chart.innerHTML = '<div style="font-family:\'Share Tech Mono\',monospace;font-size:10px;color:var(--text-dim);padding:12px 0">No threat events recorded.</div>';
    }

    const tbody = document.getElementById('recent-audit-tbody');
    tbody.innerHTML = d.recent_audit.map(e => `
      <tr>
        <td>${e.timestamp.slice(11,19)}</td>
        <td style="color:var(--green)">${e.action}</td>
        <td>${e.username||'—'}</td>
        <td style="color:var(--text-dim)">${e.ip_address||'—'}</td>
        <td><span class="badge badge-${e.result==='success'?'success':'fail'}">${e.result}</span></td>
      </tr>`).join('');
    ri();
  } catch(e) { /* silently handle */ }
}

/* ═══════════════════════════════════════════════
   NAV
═══════════════════════════════════════════════ */
function nav(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-'+page).classList.add('active');
  el.classList.add('active');
  ({ threats:loadThreats, firewall:loadFirewall, users:loadUsers, sessions:loadSessions, audit:loadAudit, rooms:initRooms }[page] || (() => {}))();
  ri();
}
function toggleForm(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
  ri();
}

/* ═══════════════════════════════════════════════
   THREATS
═══════════════════════════════════════════════ */
async function loadThreats() {
  try {
    const d = await api('/api/security/threats');
    document.getElementById('threat-tbody').innerHTML = d.recent.map(t => `
      <tr>
        <td style="color:var(--text-dim)">${t.timestamp.slice(0,19).replace('T',' ')}</td>
        <td style="font-family:'Share Tech Mono',monospace;color:var(--amber)">${t.ip_address}</td>
        <td>${t.event_type.replace(/_/g,' ')}</td>
        <td><span class="badge badge-${t.severity.toLowerCase()==='high'?'critical':t.severity.toLowerCase()}">${t.severity}</span></td>
        <td style="font-family:'Share Tech Mono',monospace;color:${t.threat_score>70?'var(--red)':'var(--amber)'}">${t.threat_score}</td>
        <td><span style="color:${t.resolved?'var(--text-dim)':'var(--red)'}">${t.resolved?'RESOLVED':'ACTIVE'}</span></td>
        <td>${t.resolved?'':'<button class="btn btn-ghost" style="font-size:9px;padding:4px 10px" onclick="resolveT('+t.id+')">Resolve</button>'}</td>
      </tr>`).join('') || '<tr><td colspan="7" style="color:var(--text-dim);text-align:center;padding:20px;font-family:\'Share Tech Mono\',monospace;font-size:10px">No threats detected</td></tr>';
    ri();
  } catch(e) {}
}
async function resolveT(id) {
  try {
    await api(`/api/security/threats/${id}/resolve`, { method:'POST' });
    toast('Threat resolved', 'green');
    addFeedEvent('info','THREAT_RESOLVED',`#${id}`,'—');
    loadThreats(); loadDashboard();
  } catch(e) { toast(e.message,'red'); }
}

/* ═══════════════════════════════════════════════
   FIREWALL
═══════════════════════════════════════════════ */
async function loadFirewall() {
  try {
    const rules = await api('/api/security/firewall');
    document.getElementById('fw-tbody').innerHTML = rules.map(r => `
      <tr>
        <td style="color:var(--text-dim);font-family:'Share Tech Mono',monospace">${r.id}</td>
        <td><span class="badge badge-${r.rule_type}">${r.rule_type.replace(/_/g,' ')}</span></td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px">${r.value}</td>
        <td><span class="badge badge-${r.action}">${r.action.toUpperCase()}</span></td>
        <td style="font-family:'Share Tech Mono',monospace;color:var(--text-dim)">${r.hits}</td>
        <td style="color:var(--text-dim);font-size:11px">${r.description||'—'}</td>
        <td><button class="btn btn-red" style="font-size:9px;padding:4px 10px" onclick="deleteFWRule(${r.id})"><i data-lucide="trash-2"></i></button></td>
      </tr>`).join('');
    ri();
  } catch(e) {}
}
async function addFWRule() {
  const v = document.getElementById('fw-value').value.trim();
  if (!v) { toast('Enter a value','red'); return; }
  try {
    await api('/api/security/firewall', { method:'POST', body:{ rule_type:document.getElementById('fw-type').value, value:v, action:document.getElementById('fw-action').value, description:document.getElementById('fw-desc').value.trim() }});
    toast('Rule added','green');
    addFeedEvent('info','FW_RULE_ADDED',v,'—');
    document.getElementById('add-rule-form').style.display='none';
    loadFirewall();
  } catch(e) { toast(e.message,'red'); }
}
async function deleteFWRule(id) {
  try {
    await api(`/api/security/firewall/${id}`,{method:'DELETE'});
    toast('Rule deleted','amber');
    addFeedEvent('high','FW_RULE_REMOVED',`#${id}`,'—');
    loadFirewall();
  } catch(e) { toast(e.message,'red'); }
}

/* ═══════════════════════════════════════════════
   USERS
═══════════════════════════════════════════════ */
async function loadUsers() {
  try {
    const users = await api('/api/security/users');
    document.getElementById('users-tbody').innerHTML = users.map(u => {
      const locked = u.locked_until && new Date(u.locked_until+'Z') > new Date();
      return `<tr>
        <td style="font-family:'Share Tech Mono',monospace">${u.username}</td>
        <td><span class="badge badge-${u.role}">${u.role}</span></td>
        <td>${u.totp_enabled?'<span style="color:var(--green);font-family:\'Share Tech Mono\',monospace;font-size:10px">✓ ON</span>':'<span style="color:var(--text-dim);font-family:\'Share Tech Mono\',monospace;font-size:10px">OFF</span>'}</td>
        <td style="font-family:'Share Tech Mono',monospace;color:${u.fail_count>0?'var(--amber)':'var(--text-dim)'}">${u.fail_count}</td>
        <td><span class="badge ${locked?'badge-block':'badge-success'}">${locked?'LOCKED':'ACTIVE'}</span></td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim)">${u.last_login?u.last_login.slice(0,16).replace('T',' '):'Never'}</td>
        <td>${locked?`<button class="btn btn-ghost" style="font-size:9px;padding:4px 9px" onclick="unlockUser(${u.id})"><i data-lucide="lock-open"></i></button>`:'—'}</td>
      </tr>`;
    }).join('');
    ri();
  } catch(e) {}
}
function checkPwStrength(pw) {
  const bar=document.getElementById('pw-strength-bar'),fill=document.getElementById('pw-strength-fill'),lbl=document.getElementById('pw-strength-label');
  if(!pw){bar.style.display='none';return;}
  bar.style.display='block';
  let s=0,issues=[];
  if(pw.length>=8)s+=25;else issues.push('Min 8 chars');
  if(/[A-Z]/.test(pw))s+=25;else issues.push('Add uppercase');
  if(/[0-9]/.test(pw))s+=25;else issues.push('Add number');
  if(/[^A-Za-z0-9]/.test(pw))s+=25;else issues.push('Add symbol');
  const labels={25:'Weak',50:'Fair',75:'Strong',100:'Excellent'};
  const colors={Weak:'var(--red)',Fair:'var(--amber)',Strong:'var(--blue)',Excellent:'var(--green)'};
  const l=labels[s]||'Weak';
  fill.style.width=s+'%';fill.style.background=colors[l];
  lbl.textContent=l+(issues.length?' — '+issues[0]:'');lbl.style.color=colors[l];
}
async function addUser() {
  const u=document.getElementById('new-uname').value.trim(),p=document.getElementById('new-upass').value,r=document.getElementById('new-urole').value;
  if(!u||!p){toast('Fill all fields','red');return;}
  try {
    await api('/api/security/users',{method:'POST',body:{username:u,password:p,role:r}});
    toast(`User "${u}" created`,'green');
    addFeedEvent('info','USER_CREATED',u,'—');
    document.getElementById('add-user-form').style.display='none';
    document.getElementById('new-uname').value='';document.getElementById('new-upass').value='';
    document.getElementById('pw-strength-bar').style.display='none';
    loadUsers();
  } catch(e) { toast(e.message,'red'); }
}
async function unlockUser(id) {
  try {
    await api(`/api/security/users/${id}/unlock`,{method:'POST'});
    toast('User unlocked','green');
    loadUsers();
  } catch(e) { toast(e.message,'red'); }
}

/* ═══════════════════════════════════════════════
   SESSIONS
═══════════════════════════════════════════════ */
async function loadSessions() {
  try {
    const sessions = await api('/api/security/sessions');
    document.getElementById('sessions-tbody').innerHTML = sessions.map(s => `
      <tr>
        <td style="font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--text-dim)">${String(s.id).slice(0,14)}…</td>
        <td style="font-family:'Share Tech Mono',monospace;color:var(--green)">${s.username}</td>
        <td style="font-family:'Share Tech Mono',monospace;color:var(--amber)">${s.ip_address||'—'}</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim)">${(s.user_agent||'').slice(0,30)}…</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim)">${s.expires_at.slice(0,16).replace('T',' ')}</td>
        <td><button class="btn btn-red" style="font-size:9px;padding:4px 9px" onclick="revokeSession('${s.id}')"><i data-lucide="x"></i> Revoke</button></td>
      </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text-dim);font-family:\'Share Tech Mono\',monospace;font-size:10px">No active sessions</td></tr>';
    ri();
  } catch(e) {}
}
async function revokeSession(id) {
  try {
    await api(`/api/security/sessions/${id}/revoke`,{method:'POST'});
    toast('Session revoked','red');
    addFeedEvent('critical','SESSION_REVOKED',String(id).slice(0,12),'—');
    loadSessions();
  } catch(e) { toast(e.message,'red'); }
}

/* ═══════════════════════════════════════════════
   AUDIT
═══════════════════════════════════════════════ */
async function loadAudit() {
  try {
    const d = await api('/api/security/audit');
    document.getElementById('audit-tbody').innerHTML = d.entries.map(e => `
      <tr>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim)">${e.timestamp.slice(0,19).replace('T',' ')}</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px">${e.username||'—'}</td>
        <td style="color:var(--green);font-family:'Share Tech Mono',monospace;font-size:10px">${e.action}</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--text-dim)">${e.resource||'—'}</td>
        <td style="font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--amber)">${e.ip_address||'—'}</td>
        <td><span class="badge badge-${e.result==='success'?'success':'fail'}">${e.result}</span></td>
      </tr>`).join('');
    ri();
  } catch(e) {}
}
async function verifyAudit() {
  try {
    const d  = await api('/api/security/audit/verify');
    const el = document.getElementById('integrity-result');
    if (d.valid) {
      el.innerHTML=`<div class="integrity-ok"><i data-lucide="shield-check"></i> Chain intact — ${d.entries} entries verified. No tampering detected.</div>`;
      toast('Audit chain valid ✓','green');
    } else {
      el.innerHTML=`<div class="integrity-fail"><i data-lucide="alert-triangle"></i> INTEGRITY VIOLATION: ${d.issues.join(' | ')}</div>`;
      toast('Chain integrity FAILED','red');
    }
    ri();
  } catch(e) { toast(e.message,'red'); }
}

/* ═══════════════════════════════════════════════
   VAULT
═══════════════════════════════════════════════ */
async function saveSecret() {
  const k=document.getElementById('vault-key').value.trim(),v=document.getElementById('vault-val').value;
  if(!k||!v){toast('Key and value required','red');return;}
  try {
    await api('/api/security/vault',{method:'POST',body:{key:k,value:v}});
    toast(`Secret "${k}" stored`,'green');
    addFeedEvent('info','VAULT_WRITE',k,'—');
    document.getElementById('vault-val').value='';
  } catch(e) { toast(e.message,'red'); }
}
async function readSecret() {
  const k=document.getElementById('vault-key').value.trim();
  if(!k){toast('Enter key name','red');return;}
  try {
    const d=await api(`/api/security/vault/${k}`);
    const el=document.getElementById('vault-result');
    el.style.display='block';
    el.innerHTML=`<span style="color:var(--text-dim)">KEY:</span> <span style="color:var(--green)">${d.key}</span> &nbsp;|&nbsp; <span style="color:var(--text-dim)">VALUE:</span> <span style="color:var(--amber)">${d.value}</span>`;
    addFeedEvent('high','VAULT_READ',k,'—');
  } catch(e) { 
    const el=document.getElementById('vault-result');
    el.style.display='block';
    el.innerHTML=`<span style="color:var(--red)">${e.message}</span>`;
  }
}

/* ═══════════════════════════════════════════════
   ROOM CONTROL
═══════════════════════════════════════════════ */
const ROOMS=[
  {id:'living_room',   name:'Living Room',   icon:'sofa',    devices:['lights','camera','motion','lock']},
  {id:'kitchen',       name:'Kitchen',       icon:'chef-hat',devices:['lights','smoke','gas','appliances']},
  {id:'bedroom_master',name:'Master Bedroom',icon:'bed',     devices:['lights','camera','windows','climate']},
  {id:'garage',        name:'Garage',        icon:'car',     devices:['lights','door','motion','vehicle']},
  {id:'office',        name:'Home Office',   icon:'monitor', devices:['lights','network','webcam','lock']},
  {id:'bathroom',      name:'Bathroom',      icon:'droplet', devices:['lights','leak','fan','temp']}
];
const DEV_LABELS={lights:'Lighting',camera:'Security Camera',motion:'Motion Sensor',lock:'Door Lock',smoke:'Smoke Detector',gas:'Gas Sensor',appliances:'Smart Appliances',windows:'Window Sensors',climate:'Climate Control',door:'Garage Door',vehicle:'Vehicle Detection',network:'Network Security',webcam:'Webcam Privacy',leak:'Water Leak Sensor',fan:'Ventilation Fan',temp:'Temp Control'};

async function initRooms() {
  if (!roomsBuilt) {
    // Load current states from backend
    let states = {};
    try { states = await api('/api/rooms'); } catch(e) {}

    const grid = document.getElementById('room-grid');
    grid.innerHTML = ROOMS.map(room => {
      const roomStates = states[room.id] || {};
      const controls = room.devices.map(dev => {
        const on = roomStates[dev] !== false;
        return `<div class="control-row">
          <label class="dev-label">${DEV_LABELS[dev]||dev}</label>
          <label class="toggle-switch">
            <input type="checkbox" id="${dev}-${room.id}" ${on?'checked':''} data-room="${room.id}" data-device="${dev}">
            <span class="slider"></span>
          </label>
        </div>`;
      }).join('');
      return `<div class="room-card">
        <div class="room-header">
          <div class="room-name"><i data-lucide="${room.icon}"></i>${room.name}</div>
          <div class="room-status" id="status-${room.id}">
            <span class="status-dot online"></span><span>SECURE</span>
          </div>
        </div>
        <div class="room-controls">${controls}</div>
        <div class="room-alerts" id="alerts-${room.id}">
          <div class="alert-item success"><i data-lucide="check-circle"></i>All systems operational</div>
        </div>
      </div>`;
    }).join('');

    roomsBuilt = true;
    ri();

    // Single change listener — no onclick/ontouchstart conflicts
    document.getElementById('room-grid').addEventListener('change', async e => {
      const input = e.target;
      if (input.type !== 'checkbox') return;
      const room   = input.dataset.room;
      const device = input.dataset.device;
      const isOn   = input.checked;
      if (!room || !device) return;

      if (navigator.vibrate) navigator.vibrate(isOn ? 50 : [50,30,50]);

      try {
        await api(`/api/rooms/${room}/${device}`, { method:'POST', body:{ state: isOn } });
      } catch(e) {
        // Revert toggle on failure
        input.checked = !isOn;
        toast('Failed to update device','red');
        return;
      }

      updateRoomStatus(room);
      updateRoomAlert(room, device, isOn);
      const roomName = ROOMS.find(r=>r.id===room)?.name||room;
      addFeedEvent('info', isOn?'DEVICE_ON':'DEVICE_OFF', `${DEV_LABELS[device]} · ${roomName}`, 'LOCAL');
      toast(`${DEV_LABELS[device]} ${isOn?'enabled':'disabled'} in ${roomName}`, isOn?'green':'amber');
    });
  }
  ROOMS.forEach(r => updateRoomStatus(r.id));
}

function updateRoomStatus(roomId) {
  const statusEl = document.getElementById(`status-${roomId}`);
  if (!statusEl) return;
  const dot  = statusEl.querySelector('.status-dot');
  const span = statusEl.querySelector('span:not(.status-dot)');
  const room = ROOMS.find(r => r.id === roomId);
  if (!room) return;
  let active=0,total=0;
  room.devices.forEach(d => { const cb=document.getElementById(`${d}-${roomId}`); if(cb){total++;if(cb.checked)active++;} });
  if(active===total){dot.className='status-dot online';if(span)span.textContent='SECURE';}
  else if(active>=Math.ceil(total/2)){dot.className='status-dot warning';if(span)span.textContent='PARTIAL';}
  else{dot.className='status-dot offline';if(span)span.textContent='VULNERABLE';}
}

function updateRoomAlert(roomId, device, isOn) {
  const el = document.getElementById(`alerts-${roomId}`);
  if (!el) return;
  const warn = { lock:{type:'warning',icon:'alert-triangle',text:'Door lock disabled — security risk'}, camera:{type:'warning',icon:'alert-triangle',text:'Security camera offline'}, smoke:{type:'error',icon:'x-circle',text:'Smoke detector disabled — fire hazard!'}, gas:{type:'error',icon:'x-circle',text:'Gas sensor disabled — safety risk!'} };
  if (!isOn && warn[device]) {
    el.innerHTML=`<div class="alert-item ${warn[device].type}"><i data-lucide="${warn[device].icon}"></i>${warn[device].text}</div>`;
    ri(); return;
  }
  const room = ROOMS.find(r=>r.id===roomId);
  const ok = ['lock','camera','smoke','gas'].filter(d=>room.devices.includes(d)).every(d=>{ const cb=document.getElementById(`${d}-${roomId}`); return !cb||cb.checked; });
  if (ok) { el.innerHTML=`<div class="alert-item success"><i data-lucide="check-circle"></i>All security systems operational</div>`; ri(); }
}

async function setGlobalMode(mode) {
  try {
    await api('/api/rooms/global', { method:'POST', body:{ mode } });
    toast(`All rooms → ${mode.toUpperCase()} mode`, mode==='secure'?'green':mode==='standby'?'amber':'red');
    addFeedEvent('critical', `GLOBAL_${mode.toUpperCase()}`, 'All rooms', 'SYSTEM');
    // Reload room states from server
    roomsBuilt = false;
    initRooms();
  } catch(e) { toast(e.message,'red'); }
}

/* ═══════════════════════════════════════════════
   FEED + TOAST + UTILS
═══════════════════════════════════════════════ */
function addFeedEvent(level, type, details, ip) {
  feedCount++;
  document.getElementById('feed-count').textContent = feedCount;
  const feed = document.getElementById('event-feed');
  const item = document.createElement('div');
  item.className = `event-item ${level}`;
  const c = level==='critical'?'var(--red)':level==='high'?'var(--amber)':'var(--green)';
  item.innerHTML=`<div class="event-time">${new Date().toTimeString().slice(0,8)}</div><div class="event-type" style="color:${c}">${type.replace(/_/g,' ')}</div><div class="event-ip">${details} · ${ip}</div>`;
  feed.insertBefore(item, feed.firstChild);
  while (feed.children.length > 80) feed.removeChild(feed.lastChild);
}

function toast(msg, color='green') {
  const c=document.getElementById('toasts');
  const t=document.createElement('div');
  t.className='toast-msg';
  t.style.borderLeft=`3px solid var(--${color})`;
  t.style.color=`var(--${color})`;
  t.textContent=msg;
  c.appendChild(t);
  setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity 0.3s';setTimeout(()=>t.remove(),300);},3200);
}

function set(id,val){const el=document.getElementById(id);if(el)el.textContent=val;}
function styleEl(id,c){const el=document.getElementById(id);if(el)el.style.color=c;}
function ri(){if(typeof lucide!=='undefined')lucide.createIcons();}

document.addEventListener('DOMContentLoaded', () => ri());