const form = document.querySelector('#login-form');
const username = document.querySelector('#username');
const password = document.querySelector('#password');
const toggle = document.querySelector('#password-toggle');
const submit = document.querySelector('#login-submit');
const errorBox = document.querySelector('#login-error');
const capsLock = document.querySelector('#caps-lock');

function safeNextPath() {
  const value = new URLSearchParams(location.search).get('next') || '/';
  return value.startsWith('/') && !value.startsWith('//') && !value.includes('\\') && !value.startsWith('/login') ? value : '/';
}

function setError(message='') {
  errorBox.textContent = message;
}

function setLoading(loading) {
  submit.disabled = loading;
  submit.classList.toggle('is-loading', loading);
  toggle.disabled = loading;
  form.setAttribute('aria-busy', String(loading));
  // Keep credential fields enabled so password managers can inspect the form
  // when the asynchronous login succeeds and the page navigates away.
}

async function existingSession() {
  try {
    const response = await fetch('/api/auth/session', {cache:'no-store'});
    if (!response.ok) return;
    document.body.classList.add('is-leaving');
    setTimeout(() => location.replace(safeNextPath()), 180);
  } catch { /* 登录页仍可正常使用 */ }
}

toggle.addEventListener('click', () => {
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  toggle.setAttribute('aria-pressed', String(show));
  toggle.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
  password.focus();
});

password.addEventListener('keyup', event => {
  capsLock.textContent = event.getModifierState?.('CapsLock') ? '大写锁定已开启' : '';
});
password.addEventListener('blur', () => { capsLock.textContent = ''; });
[username, password].forEach(field => field.addEventListener('input', () => setError()));

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submit.disabled) return;
  const account = username.value.trim();
  const secret = password.value;
  if (!account || !secret) {
    setError('请输入用户名和密码');
    (account ? password : username).focus();
    return;
  }
  username.value = account;
  password.type = 'password';
  toggle.setAttribute('aria-pressed', 'false');
  toggle.setAttribute('aria-label', '显示密码');
  setLoading(true);
  setError();
  try {
    const response = await fetch('/api/auth/login', {
      method:'POST',
      cache:'no-store',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:account, password:secret}),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || '登录失败，请稍后重试');
    // Save prompts must see the credentials that actually authenticated,
    // even if an input changed while the request was in flight.
    username.value = account;
    password.value = secret;
    document.body.classList.add('is-leaving');
    setTimeout(() => location.replace(safeNextPath()), 260);
  } catch (error) {
    setError(error.message || '登录失败，请稍后重试');
    password.select();
    setLoading(false);
  }
});

existingSession();
