// main.js - manejador central
const apiUrl = 'https://sid-restapi.onrender.com';

// Debug panel (múltiples páginas pueden tener este id)
function debugWrite(obj) {
  const dbg = document.querySelectorAll('#debugPanel');
  const text = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  dbg.forEach(d => d.textContent = text);
  console.log('DEBUG:', obj);
}

/* ---------- helpers storage for local fallback scores (keeps offline fallback) ---------- */
const LOCAL_SCORES_KEY = 'localScores';
function readLocalScores(){ try { return JSON.parse(localStorage.getItem(LOCAL_SCORES_KEY)) || {}; } catch { return {}; } }
function writeLocalScores(o){ localStorage.setItem(LOCAL_SCORES_KEY, JSON.stringify(o)); }
function setLocalScore(user,s){ const obj=readLocalScores(); obj[user]=s; writeLocalScores(obj); }
function getLocalScore(user){ return (readLocalScores()||{})[user]; }

/* ---------- tiny dom helper ---------- */
const el = id => document.getElementById(id);

/* ---------- token extractor robusto ---------- */
function findTokenAnywhere(obj){
  if (!obj || typeof obj !== 'object') return null;
  // check known fields first
  if (obj.token) return obj.token;
  if (obj.jwt) return obj.jwt;
  if (obj.accessToken) return obj.accessToken;
  // deep search
  const visited = new Set();
  function dfs(node){
    if (!node || typeof node !== 'object' || visited.has(node)) return null;
    visited.add(node);
    for (const k of Object.keys(node)){
      const v = node[k];
      if (typeof v === 'string' && v.length>10 && /eyJ|[A-Za-z0-9\-\._~\+\/]+=*/.test(v)) return v;
      if (k.toLowerCase().includes('token') && typeof v === 'string') return v;
      if (typeof v === 'object'){
        const r = dfs(v);
        if (r) return r;
      }
    }
    return null;
  }
  return dfs(obj);
}

/* ---------- fetch wrapper: includes credentials to support cookie-based sessions ---------- */
async function callApi(path, opts = {}) {
  const { method = 'GET', body = undefined, token = null, credentials = 'omit' } = opts;
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers['x-token'] = token;

  const fetchOpts = {
    method,
    headers,
    // **por defecto usamos 'omit'** para evitar conflicto CORS con Access-Control-Allow-Origin: *
    // pero permitimos pasar credentials: 'include' si el servidor está configurado correctamente.
    credentials: credentials
  };
  if (body !== undefined) fetchOpts.body = JSON.stringify(body);

  debugWrite({ request: { url: apiUrl + path, opts: fetchOpts } });
  try {
    const res = await fetch(apiUrl + path, fetchOpts);
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch(e) { data = text; }
    debugWrite({ request: { url: apiUrl + path, opts: fetchOpts }, response: { status: res.status, body: data } });
    return { ok: res.ok, status: res.status, data, rawText: text };
  } catch (err) {
    debugWrite({ error: err.message });
    return { ok: false, status: 0, error: err };
  }
}

/* ---------- Registro: POST /api/usuarios + intento de login automático ---------- */
async function registerUser(username, password) {
  if (!username || !password) { alert('Completa username y password'); return; }
  const initialScore = Math.floor(Math.random()*1001);

  // Enviar registro (incluyendo score para intentar que servidor lo guarde)
const reg = await callApi('/api/usuarios', { method: 'POST', body: { username, password, score: initialScore }, credentials: 'omit' });

  if (!reg.ok && reg.status !== 0) {
    const msg = reg.data?.msg || reg.data?.message || reg.rawText || `status:${reg.status}`;
    alert('Error en registro: ' + msg);
    return;
  }

  // Guardar local para fallback
  setLocalScore(username, initialScore);

  // Intentar extraer token directo desde respuesta del registro
  let token = findTokenAnywhere(reg.data);
  if (token) {
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
    localStorage.setItem('score', String(initialScore));
    // sync score with server using token
    await syncScoreToServer(username, initialScore, { password });
    alert('Registro OK y token recibido. Has sido autenticado automáticamente.');
    location.href = 'session.html';
    return;
  }

  // Si no hay token JSON, intentar login automático (POST /api/auth/login).
  const loginRes = await login(username, password, { silent: true });
  if (loginRes && loginRes.ok) {
    // Si login obtuvo token se guarda en login()
    // sincronizar score al server si disponemos de token
    const tokenNow = localStorage.getItem('token');
    if (tokenNow) {
      await syncScoreToServer(username, initialScore, { password });
      alert('Registro OK. Login automático exitoso y score sincronizado.');
    } else {
      // Si no hay token tras login automático, puede que el servidor use cookies: haremos una GET con credentials include para comprobar
      const probe = await callApi(`/api/usuarios/${encodeURIComponent(username)}`, { method: 'GET' });
      if (probe.ok) {
        // servidor permitió la consulta (posiblemente por cookie), tomar score del server o fallback local
        const serverScore = probe.data?.usuario?.score ?? probe.data?.score ?? null;
        if (serverScore !== null) {
          localStorage.setItem('score', serverScore);
          setLocalScore(username, serverScore);
        } else {
          localStorage.setItem('score', String(initialScore));
        }
        localStorage.setItem('username', username);
        alert('Registro ok. Se detectó sesión por cookie (sin token JSON).');
        location.href = 'session.html';
        return;
      } else {
        alert('Registro OK pero no se pudo autenticar automáticamente. Inicia sesión manualmente.');
        location.href = 'index.html';
        return;
      }
    }
  } else {
    alert('Registro OK pero no fue posible autenticarse automáticamente; inicia sesión manualmente.');
    location.href = 'index.html';
    return;
  }
}

/* ---------- Login: POST /api/auth/login ---------- */
async function login(username, password, opts = {}) {
  const silent = opts.silent || false;
  if (!username || !password) { if(!silent) alert('Rellena username y password'); return { ok: false }; }

  const res = await callApi('/api/auth/login', { method: 'POST', body: { username, password }, credentials: 'omit' });

  if (!res.ok) {
    if (!silent) {
      const msg = res.data?.msg || res.data?.message || res.rawText || `status:${res.status}`;
      alert('Login failed: ' + msg);
    }
    if (res.status === 401 || res.status === 403) localStorage.removeItem('token');
    return { ok: false, status: res.status, data: res.data };
  }

  const token = findTokenAnywhere(res.data) || res.data?.token || res.data?.jwt || res.data?.accessToken || null;
  if (token) {
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
  } else {
    localStorage.setItem('username', username); // server pudo usar cookies
  }

  // intentar obtener score desde response o desde /api/usuarios
  let score = null;
  if (res.data?.usuario) score = res.data.usuario.score ?? res.data.usuario.points ?? res.data.usuario.puntaje;
  if (res.data?.score !== undefined) score = res.data.score;
  if (score !== null && score !== undefined) {
    localStorage.setItem('score', String(score));
    setLocalScore(username, score);
  } else {
    // intentar GET profile para ver si server devuelve score
    const prof = await callApi(`/api/usuarios/${encodeURIComponent(username)}`, { method: 'GET', token: localStorage.getItem('token') });
    if (prof.ok) {
      const s2 = prof.data?.usuario?.score ?? prof.data?.score ?? null;
      if (s2 !== null && s2 !== undefined) {
        localStorage.setItem('score', String(s2));
        setLocalScore(username, s2);
      }
    }
  }

  if (!silent) {
    alert('Login OK');
    location.href = 'session.html';
  }

  return { ok: true, token, data: res.data };
}

/* ---------- PATCH score or user data (sync) ---------- */
async function syncScoreToServer(username, score, opts = {}) {
  const password = opts.password || null;

  if (!localStorage.getItem('token')) {
    if (password) {
      const loginRes = await login(username, password, { silent: true });
      if (!loginRes.ok) return { ok: false, error: 'No autenticado' };
    } else {
      return { ok: false, error: 'No autenticado' };
    }
  }

  // Solo enviar el score
  const token = localStorage.getItem('token') || null;
  const payload = { username, data: { score } };
  let res = await callApi('/api/usuarios', { method: 'PATCH', body: payload, token, credentials: 'omit' });

  if (res.status === 401 || res.status === 403) {
    debugWrite({ syncScore: 'PATCH returned 401/403, trying re-login once' });
    if (password) {
      const loginRes = await login(username, password, { silent: true });
      if (loginRes.ok) {
        const newToken = localStorage.getItem('token');
        res = await callApi('/api/usuarios', { method: 'PATCH', body: payload, token: newToken, credentials: 'omit' });
      }
    }
  }

  if (res.ok) {
    setLocalScore(username, score);
    localStorage.setItem('score', String(score));
    debugWrite({ syncScoreSuccess: res });
    return { ok: true, data: res.data };
  } else {
    debugWrite({ syncScoreFailFinal: { primary: res } });
    return { ok: false, error: res.data || res.rawText };
  }
}

/* ---------- List users (GET /api/usuarios) ---------- */
async function fetchUsersFromServer() {
  const token = localStorage.getItem('token') || null;
  const res = await callApi('/api/usuarios', { method: 'GET', token });
  if (res.status === 401) {
    // inform user
    alert('No autorizado para listar usuarios (401). El token pudo expirar o no existir. Haz login.');
    localStorage.removeItem('token');
    return { ok: false, status: 401, data: [] };
  }
  if (!res.ok) {
    console.warn('GET /api/usuarios failed', res);
    return { ok: false, status: res.status, data: [] };
  }
  // normalize array
  let arr = [];
  if (Array.isArray(res.data)) arr = res.data;
  else if (res.data?.usuarios) arr = res.data.usuarios;
  else if (res.data?.users) arr = res.data.users;
  else {
    const maybe = Object.values(res.data || {}).find(v=>Array.isArray(v));
    if (maybe) arr = maybe;
  }
  return { ok: true, data: arr };
}

/* ---------- Merge server + local and render ---------- */
async function loadUsersListAndRender() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('Debes iniciar sesión para ver la lista de usuarios.');
    location.href = 'index.html';
    return;
  }
  const out = await fetchUsersFromServer();
  const localScores = readLocalScores();
  if (!out.ok) {
    renderMergedUsers([], localScores);
    return;
  }
  renderMergedUsers(out.data, localScores);
}

function renderMergedUsers(serverUsersArray, localScoresObj) {
  const merged = (serverUsersArray||[]).map(u=>{
    const username = u.username || u.name || u.uid || u._id || 'unknown';
    const serverScore = u.score ?? u.points ?? u.puntaje ?? null;
    const localScore = localScoresObj[username];
    const score = (serverScore !== null && serverScore !== undefined) ? Number(serverScore) : (localScore !== undefined ? Number(localScore) : 0);
    return { username, score };
  });
  // add local-only
  Object.keys(localScoresObj||{}).forEach(user => {
    if (!merged.find(m=>m.username === user)) merged.push({ username: user, score: Number(localScoresObj[user]) });
  });
  merged.sort((a,b)=> b.score - a.score);

  const tbody = el('leaderboardTableBody');
  if (tbody) {
    tbody.innerHTML = '';
    merged.forEach((u, i) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${i+1}</td><td>${escapeHtml(u.username)}</td><td>${u.score}</td>`;
      tbody.appendChild(tr);
    });
  } else {
    // maybe ul on another page
    const ul = el('usersList');
    if (ul) {
      ul.innerHTML = '';
      merged.forEach((u,i)=>{
        const li = document.createElement('li');
        li.textContent = `${i+1}. ${u.username} — ${u.score}`;
        ul.appendChild(li);
      });
    }
  }
}

/* ---------- SetUIForUserLoggedIn (session page UI) ---------- */
function SetUIForUserLoggedIn(username) {
  // if session.html present, fill info
  const sessionInfo = el('sessionInfo');
  if (sessionInfo) {
    const token = localStorage.getItem('token') || '— (no token JSON; puede usarse cookie HttpOnly)';
    const score = localStorage.getItem('score') || String(getLocalScore(username) || 0);
    sessionInfo.innerHTML = `
      <p><strong>Usuario:</strong> ${escapeHtml(username)}</p>
      <p><strong>Puntaje:</strong> ${escapeHtml(score)}</p>
      <p><strong>Token (localStorage):</strong> <small class="muted">${escapeHtml(token)}</small></p>
      <p><strong>Nota:</strong> si el servidor usa cookies HttpOnly, el token no será visible en JS pero sí será usado por fetch con credentials.</p>
    `;
  }
}

/* ---------- helpers ---------- */
function escapeHtml(s){ if (s===null||s===undefined) return ''; return String(s).replace(/[&<"']/g, m=>({'&':'&amp;','<':'&lt;','"':'&quot;',"'":'&#39;'}[m])); }

/* ---------- event bindings on DOMContentLoaded ---------- */
document.addEventListener('DOMContentLoaded', () => {
  // login form
  if (el('loginButton')) el('loginButton').addEventListener('click', (ev)=>{ ev.preventDefault(); login(el('usernameInput').value, el('passwordInput').value); });
  // register
  if (el('registerButton')) el('registerButton').addEventListener('click', (ev)=>{ ev.preventDefault(); registerUser(el('newUsername').value, el('newPassword').value); });
  // refresh users
  if (el('refreshUsersBtn')) el('refreshUsersBtn').addEventListener('click', ()=>loadUsersListAndRender());
  // session page controls
  if (el('logoutBtn')) el('logoutBtn').addEventListener('click', ()=>{ localStorage.removeItem('token'); localStorage.removeItem('username'); localStorage.removeItem('score'); location.href='index.html'; });
  if (el('refreshTokenBtn')) el('refreshTokenBtn').addEventListener('click', async ()=> {
    // prompt quick relogin (for testing)
    const u = prompt('Usuario para re-login:');
    const p = prompt('Contraseña:');
    if (u && p) { await login(u,p); location.reload(); }
  });
  
    if (el('changeScoreBtn')) el('changeScoreBtn').addEventListener('click', async (ev) => {
    ev.preventDefault();
    const username = el('scoreUserInput').value;
    const score = Number(el('newScoreInput').value);
    if (!username || isNaN(score)) {
      alert('Completa usuario y nuevo score');
      return;
    }
    const res = await syncScoreToServer(username, score);
    if (res.ok) {
      alert('Score actualizado correctamente');
      loadUsersListAndRender();
    } else {
      alert('Error al actualizar score');
    }
  });

  // If visiting users.html -> load table
  if (el('leaderboardTableBody')) loadUsersListAndRender();

  // If visiting session.html -> display session info
  const storedUser = localStorage.getItem('username');
  if (storedUser) SetUIForUserLoggedIn(storedUser);
});
