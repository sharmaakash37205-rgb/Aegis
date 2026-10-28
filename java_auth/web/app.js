/**
 * ============================================================================
 * Aegis Vault & Security Suite — Unified Client Engine
 * Full 7-Module Architecture, Zero-Knowledge Crypto & Password Recovery
 * ============================================================================
 */

const API_BASE = window.location.origin;

// SECV Binary Header Format Constants (100% Interoperable)
const CRYPTO_CONFIG = {
  MAGIC: new Uint8Array([0x53, 0x45, 0x43, 0x56]), // "SECV"
  VERSION: 1,
  SALT_SIZE: 16,
  NONCE_SIZE: 12,
  TAG_SIZE: 16,
  ITERATIONS: 600000,
  CHUNK_SIZE: 2 * 1024 * 1024, // 2 MB high-throughput streaming chunks
};

// Global App State (Sensitive credentials stored in ephemeral sessionStorage to prevent persistent XSS exposure)
let authToken = sessionStorage.getItem('aegis_auth_token') || localStorage.getItem('aegis_auth_token') || null;
let currentUser = JSON.parse(sessionStorage.getItem('aegis_user_profile') || localStorage.getItem('aegis_user_profile') || 'null');
localStorage.removeItem('aegis_auth_token');
localStorage.removeItem('aegis_user_profile');
if (authToken) sessionStorage.setItem('aegis_auth_token', authToken);
if (currentUser) sessionStorage.setItem('aegis_user_profile', JSON.stringify(currentUser));

let vaultStudioMode = 'encrypt'; // 'encrypt' or 'decrypt'
let selectedFile = null;
let selectedFileBuffer = null;
let lastResultBlob = null;
let lastResultFilename = '';
let lastSavedDesktopPath = '';
let currentDecryptedPlaintext = null;
let isProcessingCrypto = false;
let sfxEnabled = localStorage.getItem('aegis_sfx') !== 'false';
let activeAuditFilter = 'ALL';
let currentNavTab = 'identity-auth';

// High-speed chunk-safe base64 encoder for streaming IPC (uses browser C++ FileReader)
function bytesToBase64Async(bytes) {
  return new Promise((resolve) => {
    try {
      const reader = new FileReader();
      reader.onload = () => {
        const url = reader.result;
        const comma = url.indexOf(',');
        resolve(comma >= 0 ? url.slice(comma + 1) : url);
      };
      reader.onerror = () => resolve(bytesToBase64(bytes));
      reader.readAsDataURL(new Blob([bytes]));
    } catch (e) {
      resolve(bytesToBase64(bytes));
    }
  });
}

function bytesToBase64(bytes) {
  let binary = '';
  const len = bytes.byteLength;
  const step = 0x8000;
  for (let i = 0; i < len; i += step) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + step, len)));
  }
  return btoa(binary);
}

// Local Standalone Safe Storage Cache
let localSafeItems = JSON.parse(localStorage.getItem('aegis_safe_items') || '[]');
let localAuditEvents = JSON.parse(localStorage.getItem('aegis_local_audit') || '[]');

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initSFX();
  updateSFXButton();
  setupDropzone();
  checkServerHealth();
  updateSafeCountBadge();

  if (authToken) {
    verifySession();
  }

  // Keyboard Shortcuts Listener
  window.addEventListener('keydown', handleGlobalKeydown);

  // Close dropdowns on outside click
  window.addEventListener('click', (e) => {
    const dropdown = document.getElementById('profile-dropdown-menu');
    const profileBtn = document.getElementById('header-user-profile');
    if (dropdown && !dropdown.classList.contains('hidden')) {
      if (!profileBtn.contains(e.target)) {
        dropdown.classList.add('hidden');
      }
    }
  });

  // Generate initial passphrase for Fortress
  generateFortressPassphrase();
});

// ============================================================================
// NAVIGATION & TAB ROUTING (7 MODULES)
// ============================================================================

function switchNavTab(tabId) {
  const publicTab = tabId === 'identity-auth';
  if (!currentUser || !authToken) {
    if (!publicTab) {
      const feedback = document.getElementById('login-feedback');
      if (feedback) {
        showAlert(feedback, 'error', 'Please verify your user ID and password before using this service.');
      }
      switchAuthTab('login');
      return;
    }
  }

  currentNavTab = tabId;
  playSFX('click');

  // Update Nav Pills
  const pills = document.querySelectorAll('.nav-pill');
  pills.forEach(p => p.classList.remove('active'));

  const activePill = document.getElementById(`nav-${tabId}`);
  if (activePill) activePill.classList.add('active');

  // Switch View
  const views = document.querySelectorAll('.tab-view');
  views.forEach(v => v.classList.remove('active'));

  const targetView = document.getElementById(`tab-view-${tabId}`);
  if (targetView) {
    targetView.classList.add('active');
  }

  // Module Specific Triggers
  if (tabId === 'encrypted-safe') {
    renderSafeItems();
  } else if (tabId === 'security-audit') {
    loadAuditLogs();
  } else if (tabId === 'passphrase-fortress') {
    generateFortressPassphrase();
  }
}

// ============================================================================
// SERVER HEALTH & STATUS
// ============================================================================

async function checkServerHealth() {
  const statusText = document.getElementById('server-status-text');
  const statusPulse = document.getElementById('server-status-pulse');
  try {
    const res = await fetch(`${API_BASE}/api/auth/status`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const data = await res.json();
      statusPulse.classList.remove('offline');
      const minutes = Math.floor((data.uptimeSeconds || 0) / 60);
      statusText.textContent = `Connected to Node (${data.registeredUsers || 1} Users • Uptime ${minutes}m)`;
      return;
    }
  } catch (err) {}

  statusPulse.classList.add('offline');
  statusText.textContent = 'Node Offline (Local Engine Active)';
}

// ============================================================================
// IDENTITY & AUTHENTICATION (LOGIN / REGISTER / FORGOT PASSWORD)
// ============================================================================

function switchAuthTab(tab) {
  playSFX('click');
  const tabLogin = document.getElementById('tab-login');
  const tabRegister = document.getElementById('tab-register');
  const tabForgot = document.getElementById('tab-forgot');
  const formLogin = document.getElementById('login-form');
  const formRegister = document.getElementById('register-form');
  const formForgot = document.getElementById('forgot-form');

  [tabLogin, tabRegister, tabForgot].forEach(t => t && t.classList.remove('active'));
  [formLogin, formRegister, formForgot].forEach(f => f && f.classList.add('hidden'));

  clearAlerts();

  if (tab === 'login') {
    if (tabLogin) tabLogin.classList.add('active');
    if (formLogin) formLogin.classList.remove('hidden');
  } else if (tab === 'register') {
    if (tabRegister) tabRegister.classList.add('active');
    if (formRegister) formRegister.classList.remove('hidden');
  } else if (tab === 'forgot') {
    if (tabForgot) tabForgot.classList.add('active');
    if (formForgot) formForgot.classList.remove('hidden');
    // Reset forgot password step
    document.getElementById('forgot-step-1').classList.remove('hidden');
    document.getElementById('forgot-step-2').classList.add('hidden');
  }
}

function handleSecurityQuestionChange(val) {
  const customBox = document.getElementById('reg-custom-question-box');
  if (val === '__custom__') {
    customBox.classList.remove('hidden');
    document.getElementById('reg-custom-question').required = true;
  } else {
    customBox.classList.add('hidden');
    document.getElementById('reg-custom-question').required = false;
  }
}

async function handleLogin(e) {
  e.preventDefault();
  playSFX('click');
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const feedback = document.getElementById('login-feedback');
  const btn = document.getElementById('btn-login-submit');

  clearAlerts();
  btn.disabled = true;
  btn.innerHTML = '<span>⏳ Deriving PBKDF2 Key...</span>';

  try {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      playSFX('unlock');
      authToken = data.token;
      currentUser = data.user;
      sessionStorage.setItem('aegis_auth_token', authToken);
      sessionStorage.setItem('aegis_user_profile', JSON.stringify(currentUser));
      localStorage.removeItem('aegis_auth_token');
      localStorage.removeItem('aegis_user_profile');
      showAuthenticatedUI();
      logLocalAuditEvent('LOGIN_SUCCESS', currentUser.username, 'Login authenticated');
      setTimeout(() => {
        switchNavTab('vault-studio');
      }, 500);
    } else {
      playSFX('error');
      showAlert(feedback, 'error', data.error || 'Invalid credentials or account locked.');
      logLocalAuditEvent('LOGIN_FAILED', username, data.error || 'Authentication failed');
    }
  } catch (err) {
    playSFX('error');
    showAlert(feedback, 'error', 'Authentication server unavailable. Start the Aegis security node and try again.');
    logLocalAuditEvent('LOGIN_FAILED', username, 'Authentication server unavailable');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🚀 Authenticate & Access Vault</span>';
  }
}

async function handleRegister(e) {
  e.preventDefault();
  playSFX('click');
  const username = document.getElementById('reg-username').value.trim();
  const displayName = document.getElementById('reg-displayname').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm = document.getElementById('reg-confirm').value;
  const qSelect = document.getElementById('reg-security-question').value;
  const securityQuestion = qSelect === '__custom__'
    ? document.getElementById('reg-custom-question').value.trim()
    : qSelect;
  const securityAnswer = document.getElementById('reg-security-answer').value.trim();
  const feedback = document.getElementById('reg-feedback');
  const btn = document.getElementById('btn-reg-submit');

  clearAlerts();

  if (!displayName || !email) {
    playSFX('error');
    showAlert(feedback, 'error', 'Full name and email address are required.');
    return;
  }

  if (password.length > 128) {
    playSFX('error');
    showAlert(feedback, 'error', 'Password must not exceed 128 characters.');
    return;
  }

  if (password !== confirm) {
    playSFX('error');
    showAlert(feedback, 'error', 'Passwords do not match.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span>⏳ Hashing Credentials (600K Iters)...</span>';

  try {
    const res = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        displayName,
        email,
        password,
        securityQuestion,
        securityAnswer
      })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      playSFX('success');
      authToken = data.token;
      currentUser = data.user;
      sessionStorage.setItem('aegis_auth_token', authToken);
      sessionStorage.setItem('aegis_user_profile', JSON.stringify(currentUser));
      localStorage.removeItem('aegis_auth_token');
      localStorage.removeItem('aegis_user_profile');
      showAuthenticatedUI();
      logLocalAuditEvent('REGISTER_SUCCESS', currentUser.username, 'Account created successfully');
      setTimeout(() => {
        switchNavTab('vault-studio');
      }, 500);
    } else {
      playSFX('error');
      showAlert(feedback, 'error', data.error || 'Registration failed.');
      logLocalAuditEvent('REGISTER_FAILED', username, data.error || 'Registration error');
    }
  } catch (err) {
    showAlert(feedback, 'error', 'Authentication server unavailable. Start the Aegis security node and try again.');
    logLocalAuditEvent('REGISTER_FAILED', username, 'Authentication server unavailable');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>✨ Create Secure Account</span>';
  }
}

// ============================================================================
// FORGOT PASSWORD / ZERO-KNOWLEDGE RECOVERY WORKFLOW
// ============================================================================

let recoveryUsername = '';

async function lookupSecurityQuestion() {
  playSFX('click');
  const input = document.getElementById('forgot-username').value.trim();
  const feedback = document.getElementById('forgot-feedback');

  if (!input) {
    showAlert(feedback, 'error', 'Please enter your username or registered email.');
    return;
  }

  clearAlerts();

  try {
    const res = await fetch(`${API_BASE}/api/auth/forgot-password/get-question`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: input })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      recoveryUsername = data.username || input;
      document.getElementById('forgot-question-text').textContent = data.question || 'What was the name of your first security key or pet?';
      document.getElementById('forgot-step-1').classList.add('hidden');
      document.getElementById('forgot-step-2').classList.remove('hidden');
      playSFX('success');
    } else {
      playSFX('error');
      showAlert(feedback, 'error', data.error || 'No account found with this username.');
    }
  } catch (err) {
    playSFX('error');
    showAlert(feedback, 'error', 'Security server is unavailable. Please start the Aegis security node to reset your password.');
  }
}

async function handleForgotPasswordSubmit(e) {
  e.preventDefault();
  playSFX('click');
  const answer = document.getElementById('forgot-answer').value.trim();
  const newPassword = document.getElementById('forgot-new-password').value;
  const confirmPassword = document.getElementById('forgot-confirm-password').value;
  const feedback = document.getElementById('forgot-feedback');
  const btn = document.getElementById('btn-forgot-reset');

  clearAlerts();

  if (newPassword !== confirmPassword) {
    playSFX('error');
    showAlert(feedback, 'error', 'New passwords do not match.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span>⏳ Verifying Challenge & Deriving Key...</span>';

  try {
    const res = await fetch(`${API_BASE}/api/auth/forgot-password/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: recoveryUsername,
        answer: answer,
        newPassword: newPassword
      })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      playSFX('success');
      showAlert(feedback, 'success', data.message || 'Password reset successfully! Redirecting to login...');
      logLocalAuditEvent('PASSWORD_RESET_SUCCESS', recoveryUsername, 'Password reset via security challenge');
      setTimeout(() => {
        switchAuthTab('login');
        document.getElementById('login-username').value = recoveryUsername;
      }, 1500);
    } else {
      playSFX('error');
      showAlert(feedback, 'error', data.error || 'Incorrect security answer.');
      logLocalAuditEvent('PASSWORD_RESET_FAILED', recoveryUsername, 'Failed security challenge verification');
    }
  } catch (err) {
    playSFX('error');
    showAlert(feedback, 'error', 'Password reset server is unavailable. Please start the Aegis security node and try again.');
    logLocalAuditEvent('PASSWORD_RESET_FAILED', recoveryUsername, 'Server unavailable for password reset');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🔄 Reset Master Password & Unlock</span>';
  }
}

// ============================================================================
// AUTHENTICATED UI & PROFILE BINDING
// ============================================================================

async function verifySession() {
  try {
    const res = await fetch(`${API_BASE}/api/auth/verify`, {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });

    if (res.ok) {
      const data = await res.json();
      if (data.valid) {
        currentUser = data.user;
        showAuthenticatedUI();
        return;
      }
    }
    sessionStorage.removeItem('aegis_auth_token');
    sessionStorage.removeItem('aegis_user_profile');
    localStorage.removeItem('aegis_auth_token');
    localStorage.removeItem('aegis_user_profile');
    authToken = null;
  } catch (err) {
    sessionStorage.removeItem('aegis_auth_token');
    sessionStorage.removeItem('aegis_user_profile');
    localStorage.removeItem('aegis_auth_token');
    localStorage.removeItem('aegis_user_profile');
    authToken = null;
    currentUser = null;
  }
}

function showAuthenticatedUI() {
  if (!currentUser) return;

  document.getElementById('auth-gateway-screen').classList.add('hidden');
  document.getElementById('app-workspace').classList.remove('hidden');

  const username = currentUser.username || 'User';
  const displayName = currentUser.displayName || username;
  const initial = displayName.charAt(0).toUpperCase();

  // 1. Top Header Profile Widget
  const profileWidget = document.getElementById('header-user-profile');
  if (profileWidget) {
    profileWidget.classList.remove('hidden');
    document.getElementById('header-avatar-initial').textContent = initial;
    document.getElementById('header-display-name').textContent = displayName;
    document.getElementById('header-username').textContent = `USER ID • ${username}`;
  }

  // 2. Dropdown Menu
  document.getElementById('dropdown-avatar-initial').textContent = initial;
  document.getElementById('dropdown-display-name').textContent = displayName;
  document.getElementById('dropdown-email').textContent = currentUser.email || `${username}@aegis.vault`;
  document.getElementById('dropdown-created').textContent = (currentUser.createdAt || '').substring(0, 10) || 'Active';
  if (authToken) {
    document.getElementById('dropdown-token').textContent = `${authToken.substring(0, 10)}...`;
  }

  // 3. Identity Tab Account Dashboard View
  document.getElementById('auth-forms-container').classList.add('hidden');
  document.getElementById('auth-dashboard-container').classList.remove('hidden');

  document.getElementById('dash-welcome-title').textContent = `Welcome, ${displayName}`;
  document.getElementById('dash-username-val').textContent = username;
  document.getElementById('dash-displayname-val').textContent = displayName;
  document.getElementById('dash-email-val').textContent = currentUser.email || 'Not specified';
  document.getElementById('dash-created-val').textContent = (currentUser.createdAt || '').substring(0, 10) || 'Recent';
  document.getElementById('dash-token-val').textContent = authToken || 'Local Authenticated Session';
}

function toggleProfileDropdown() {
  const dropdown = document.getElementById('profile-dropdown-menu');
  if (dropdown) dropdown.classList.toggle('hidden');
}

async function handleLogout() {
  playSFX('lock');
  if (authToken && !authToken.startsWith('local_')) {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
    } catch (e) {}
  }

  if (currentUser) {
    logLocalAuditEvent('LOGOUT', currentUser.username, 'User logged out');
  }

  sessionStorage.removeItem('aegis_auth_token');
  sessionStorage.removeItem('aegis_user_profile');
  localStorage.removeItem('aegis_auth_token');
  localStorage.removeItem('aegis_user_profile');
  authToken = null;
  currentUser = null;

  document.getElementById('auth-gateway-screen').classList.remove('hidden');
  document.getElementById('app-workspace').classList.add('hidden');
  document.getElementById('header-user-profile').classList.add('hidden');
  document.getElementById('profile-dropdown-menu').classList.add('hidden');
  document.getElementById('auth-dashboard-container').classList.add('hidden');
  document.getElementById('auth-forms-container').classList.remove('hidden');
  switchNavTab('identity-auth');
  switchAuthTab('login');
}

// ============================================================================
// TAB 1: VAULT STUDIO (ENCRYPTION & DECRYPTION WORKSTATION)
// ============================================================================

function setVaultStudioMode(mode) {
  vaultStudioMode = mode;
  playSFX('click');

  const btnEnc = document.getElementById('btn-mode-enc');
  const btnDec = document.getElementById('btn-mode-dec');
  const title = document.getElementById('vault-mode-title');
  const sub = document.getElementById('vault-mode-subtitle');
  const badgeIcon = document.getElementById('vault-mode-badge-icon');
  const dropText = document.getElementById('dropzone-text');
  const dropSub = document.getElementById('dropzone-subtext');
  const passLabel = document.getElementById('vault-passphrase-label');

  document.getElementById('vault-result-box').classList.add('hidden');

  if (mode === 'encrypt') {
    btnEnc.classList.add('active');
    btnDec.classList.remove('active');
    badgeIcon.textContent = '🔒';
    title.textContent = 'Encrypt File to SECV Vault';
    sub.textContent = 'Authenticated AES-256-GCM chunk streaming with anti-tamper AAD';
    dropText.textContent = 'Drag & drop your file here, or click to browse';
    dropSub.textContent = 'Supports all file types (Documents, Archives, Images, Databases)';
    passLabel.textContent = 'Master Encryption Passphrase';
  } else {
    btnDec.classList.add('active');
    btnEnc.classList.remove('active');
    badgeIcon.textContent = '🔓';
    title.textContent = 'Decrypt SECV .vault File';
    sub.textContent = 'Verify 128-bit authentication tags and restore original plaintext';
    dropText.textContent = 'Drag & drop your .vault file here, or click to browse';
    dropSub.textContent = 'Restores original file with bit-for-bit accuracy';
    passLabel.textContent = 'Decryption Passphrase';
  }

  updateVaultButtonState();
}

function setupDropzone() {
  const dropzone = document.getElementById('vault-dropzone');
  if (!dropzone) return;

  ['dragenter', 'dragover'].forEach(e => {
    dropzone.addEventListener(e, (evt) => {
      evt.preventDefault();
      dropzone.style.borderColor = 'var(--cyan)';
    });
  });

  ['dragleave', 'drop'].forEach(e => {
    dropzone.addEventListener(e, (evt) => {
      evt.preventDefault();
      dropzone.style.borderColor = 'rgba(51, 65, 85, 0.8)';
    });
  });

  dropzone.addEventListener('drop', (evt) => {
    const files = evt.dataTransfer.files;
    if (files && files.length > 0) {
      handleVaultFile(files);
    }
  });
}

function handleVaultFile(files) {
  if (!files || files.length === 0) return;
  selectedFile = files[0];
  playSFX('click');

  // Store only the File reference — do NOT load entire file into memory.
  // File chunks are read on-demand during encryption/decryption via File.slice()
  document.getElementById('selected-file-name').textContent = selectedFile.name;
  document.getElementById('selected-file-meta').textContent = `${formatBytes(selectedFile.size)} • Ready`;
  document.getElementById('vault-dropzone').classList.add('hidden');
  document.getElementById('vault-file-selected-box').classList.remove('hidden');

  if (selectedFile.name.endsWith('.vault') || selectedFile.name.endsWith('.enc')) {
    if (vaultStudioMode !== 'decrypt') setVaultStudioMode('decrypt');
  }

  updateVaultButtonState();
}

function clearVaultFile() {
  selectedFile = null;
  selectedFileBuffer = null;
  document.getElementById('vault-dropzone').classList.remove('hidden');
  document.getElementById('vault-file-selected-box').classList.add('hidden');
  document.getElementById('vault-result-box').classList.add('hidden');
  document.getElementById('vault-file-input').value = '';
  updateVaultButtonState();
}

function updateVaultButtonState() {
  const btn = document.getElementById('btn-vault-action');
  const label = document.getElementById('btn-vault-action-label');
  const pass = document.getElementById('vault-passphrase-input').value;

  if (!selectedFile) {
    btn.disabled = true;
    label.textContent = 'Select a file to begin';
    return;
  }

  if (!pass) {
    btn.disabled = true;
    label.textContent = 'Enter passphrase to proceed';
    return;
  }

  btn.disabled = false;
  label.textContent = vaultStudioMode === 'encrypt'
    ? `🔒 Encrypt '${selectedFile.name}' to .vault`
    : `🔓 Decrypt '${selectedFile.name}'`;
}

function quickGeneratePassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+';
  const array = new Uint8Array(20);
  crypto.getRandomValues(array);
  let pwd = '';
  for (let i = 0; i < array.length; i++) {
    pwd += alphabet[array[i] % alphabet.length];
  }
  const input = document.getElementById('vault-passphrase-input');
  input.value = pwd;
  input.type = 'text';
  updateVaultButtonState();
  playSFX('click');
}

function copyPassphraseInput() {
  const input = document.getElementById('vault-passphrase-input');
  if (input.value) {
    navigator.clipboard.writeText(input.value);
    playSFX('success');
  }
}

// ============================================================================
// ZERO-KNOWLEDGE STREAMING AES-256-GCM CRYPTO ENGINE
// ============================================================================

async function executeVaultCrypto() {
  if (isProcessingCrypto || !selectedFile) return;

  const password = document.getElementById('vault-passphrase-input').value;
  if (!password) return;

  isProcessingCrypto = true;
  playSFX('click');

  const btn = document.getElementById('btn-vault-action');
  const progressBox = document.getElementById('vault-progress-box');
  const progressFill = document.getElementById('vault-progress-fill');
  const progressPct = document.getElementById('vault-progress-pct');
  const progressStatus = document.getElementById('vault-progress-status');
  const resultBox = document.getElementById('vault-result-box');

  btn.disabled = true;
  progressBox.classList.remove('hidden');
  resultBox.classList.add('hidden');

  const startTime = performance.now();

  try {
    let pySession = null;

    if (vaultStudioMode === 'encrypt') {
      progressStatus.textContent = 'Deriving PBKDF2 Key (600,000 iterations)...';
      progressPct.textContent = '10%';
      progressFill.style.width = '10%';

      // 1. Generate CSPRNG Salt (16B) & Base Nonce (12B)
      const salt = crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.SALT_SIZE));
      const baseNonce = crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.NONCE_SIZE));

      // 2. Derive AES-GCM Key via PBKDF2
      const key = await deriveKeyFromPassword(password, salt, CRYPTO_CONFIG.ITERATIONS);

      progressStatus.textContent = 'Streaming AES-256-GCM Chunks...';
      progressPct.textContent = '35%';
      progressFill.style.width = '35%';

      const totalBytes = selectedFile.size;
      const chunks = [];
      lastResultFilename = `${selectedFile.name}.vault`;
      lastSavedDesktopPath = '';

      // Initialize native Desktop write stream if in pywebview window
      if (window.pywebview && window.pywebview.api && window.pywebview.api.start_save_session) {
        try {
          pySession = await window.pywebview.api.start_save_session(lastResultFilename);
        } catch (sessErr) {
          console.warn('Could not start pywebview save session:', sessErr);
        }
      }

      // Write SECV Binary Header (37 Bytes)
      // Format: [MAGIC: 4B "SECV"] [VERSION: 1B 0x01] [CHUNK_SIZE: 4B] [SALT: 16B] [BASE_NONCE: 12B]
      const header = new Uint8Array(37);
      header.set(CRYPTO_CONFIG.MAGIC, 0);
      header[4] = CRYPTO_CONFIG.VERSION;
      const chunkDv = new DataView(header.buffer, 5, 4);
      chunkDv.setUint32(0, CRYPTO_CONFIG.CHUNK_SIZE, false);
      header.set(salt, 9);
      header.set(baseNonce, 25);
      chunks.push(header);

      if (pySession) {
        await window.pywebview.api.append_chunk(pySession.session_id, await bytesToBase64Async(header));
      }

      let offset = 0;
      let chunkIndex = 0;
      const totalChunks = Math.ceil(totalBytes / CRYPTO_CONFIG.CHUNK_SIZE) || 1;
      let lastReportedPct = 35;

      while (offset < totalBytes || totalBytes === 0) {
        const isLast = (offset + CRYPTO_CONFIG.CHUNK_SIZE >= totalBytes) ? 1 : 0;
        const chunkLen = Math.min(CRYPTO_CONFIG.CHUNK_SIZE, totalBytes - offset);
        // Stream: read only this chunk from file instead of entire file in memory
        const chunkPlaintext = totalBytes === 0 ? new Uint8Array(0) : new Uint8Array(await selectedFile.slice(offset, offset + chunkLen).arrayBuffer());

        // Deterministic Chunk Nonce
        const chunkNonce = computeChunkNonce(baseNonce, chunkIndex);

        // AAD Anti-Tamper payload: [MAGIC 4B] [VER 1B] [CHUNK_INDEX 8B BigEndian] [IS_LAST 4B BigEndian] = 17 Bytes
        const aad = new Uint8Array(17);
        aad.set(CRYPTO_CONFIG.MAGIC, 0);
        aad[4] = CRYPTO_CONFIG.VERSION;
        const dv = new DataView(aad.buffer, 5, 12);
        dv.setUint32(0, 0, false);
        dv.setUint32(4, chunkIndex, false);
        dv.setUint32(8, isLast, false);

        const ciphertextBuffer = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: chunkNonce, additionalData: aad, tagLength: 128 },
          key,
          chunkPlaintext
        );

        const cipherBytes = new Uint8Array(ciphertextBuffer);

        // Stream chunk directly to Python desktop saver
        if (pySession) {
          await window.pywebview.api.append_chunk(pySession.session_id, await bytesToBase64Async(cipherBytes));
        }
        if (!pySession || totalBytes <= 50 * 1024 * 1024) {
          chunks.push(cipherBytes);
        }

        offset += chunkLen;
        chunkIndex++;

        // Throttle DOM updates to avoid layout/style thrashing
        const pct = Math.min(95, Math.floor(35 + (offset / totalBytes) * 60));
        if (pct !== lastReportedPct) {
          lastReportedPct = pct;
          progressPct.textContent = `${pct}%`;
          progressFill.style.width = `${pct}%`;
        }

        if (isLast || totalBytes === 0) break;
      }

      if (pySession) {
        lastSavedDesktopPath = await window.pywebview.api.finish_save_session(pySession.session_id);
      }

      const finalBlob = (!pySession || totalBytes <= 50 * 1024 * 1024)
        ? new Blob(chunks, { type: 'application/octet-stream' })
        : new Blob([], { type: 'application/octet-stream' });
      lastResultBlob = finalBlob;

      progressFill.style.width = '100%';
      progressPct.textContent = '100%';
      progressStatus.textContent = 'Complete!';

      const elapsedMs = performance.now() - startTime;
      const speedMBps = ((totalBytes / (1024 * 1024)) / (elapsedMs / 1000)).toFixed(2);
      document.getElementById('vault-speed-lbl').textContent = `⚡ Speed: ${speedMBps} MB/s`;
      document.getElementById('vault-chunks-lbl').textContent = `📦 Chunks: ${chunkIndex}`;

      // Show Result
      showCryptoSuccess('Encryption Complete!', `File encrypted to SECV format (${formatBytes(finalBlob.size)}).`, lastResultFilename, false);
      playSFX('lock');
      logLocalAuditEvent('ENCRYPT_SUCCESS', currentUser ? currentUser.username : 'User', `Encrypted '${selectedFile.name}'`);

    } else {
      // DECRYPTION
      progressStatus.textContent = 'Parsing SECV Header & Deriving Key...';
      progressPct.textContent = '15%';
      progressFill.style.width = '15%';

      const totalLen = selectedFile.size;
      if (totalLen < 37) {
        throw new Error('File is too short to be a valid SECV .vault archive.');
      }

      // Stream: read only the 37-byte header from file (not the entire file)
      const headerBytes = new Uint8Array(await selectedFile.slice(0, 37).arrayBuffer());

      // Check Magic
      const magic = headerBytes.slice(0, 4);
      if (magic[0] !== 0x53 || magic[1] !== 0x45 || magic[2] !== 0x43 || magic[3] !== 0x56) {
        throw new Error('Invalid magic identifier. Not a SECV vault file.');
      }

      const version = headerBytes[4];
      if (version !== 1) {
        throw new Error(`Unsupported SECV version: ${version}`);
      }

      // Dynamically extract chunk size from header (bytes 5-8) for 100% interoperability with all file versions
      const chunkDv = new DataView(headerBytes.buffer, 5, 4);
      const chunkSize = chunkDv.getUint32(0, false) || CRYPTO_CONFIG.CHUNK_SIZE;

      const salt = headerBytes.slice(9, 25);
      const baseNonce = headerBytes.slice(25, 37);

      const key = await deriveKeyFromPassword(password, salt, CRYPTO_CONFIG.ITERATIONS);

      let outName = selectedFile.name.replace(/\.(vault|enc)$/i, '');
      if (outName === selectedFile.name) outName = `decrypted_${outName}`;
      lastResultFilename = outName;
      lastSavedDesktopPath = '';

      // Initialize native Desktop write stream if in pywebview window
      if (window.pywebview && window.pywebview.api && window.pywebview.api.start_save_session) {
        try {
          pySession = await window.pywebview.api.start_save_session(lastResultFilename);
        } catch (sessErr) {
          console.warn('Could not start pywebview save session:', sessErr);
        }
      }

      progressStatus.textContent = 'Verifying Authentication Tags & Decrypting...';
      progressPct.textContent = '40%';
      progressFill.style.width = '40%';

      let offset = 37;
      let chunkIndex = 0;
      const decryptedChunks = [];
      let lastReportedPct = 40;

      while (offset < totalLen) {
        const remaining = totalLen - offset;
        const isLast = (remaining <= chunkSize + CRYPTO_CONFIG.TAG_SIZE) ? 1 : 0;
        const ciphertextLen = isLast ? remaining : chunkSize + CRYPTO_CONFIG.TAG_SIZE;

        // Stream: read only this encrypted chunk from file
        const ciphertext = new Uint8Array(await selectedFile.slice(offset, offset + ciphertextLen).arrayBuffer());
        const chunkNonce = computeChunkNonce(baseNonce, chunkIndex);

        const aad = new Uint8Array(17);
        aad.set(CRYPTO_CONFIG.MAGIC, 0);
        aad[4] = CRYPTO_CONFIG.VERSION;
        const dv = new DataView(aad.buffer, 5, 12);
        dv.setUint32(0, 0, false);
        dv.setUint32(4, chunkIndex, false);
        dv.setUint32(8, isLast, false);

        let plaintextBuffer;
        try {
          plaintextBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: chunkNonce, additionalData: aad, tagLength: 128 },
            key,
            ciphertext
          );
        } catch (e) {
          if (pySession && window.pywebview && window.pywebview.api) {
            try { await window.pywebview.api.cancel_save_session(pySession.session_id); } catch (ce) {}
            pySession = null;
          }
          throw new Error('Authentication Failed: Incorrect passphrase or tampered file.');
        }

        const plainBytes = new Uint8Array(plaintextBuffer);

        // Stream decrypted chunk directly to Python desktop saver
        if (pySession) {
          await window.pywebview.api.append_chunk(pySession.session_id, await bytesToBase64Async(plainBytes));
        }
        if (!pySession || totalLen <= 50 * 1024 * 1024) {
          decryptedChunks.push(plainBytes);
        }

        offset += ciphertextLen;
        chunkIndex++;

        // Throttle DOM updates
        const pct = Math.min(95, Math.floor(40 + (offset / totalLen) * 55));
        if (pct !== lastReportedPct) {
          lastReportedPct = pct;
          progressPct.textContent = `${pct}%`;
          progressFill.style.width = `${pct}%`;
        }

        if (isLast) break;
      }

      if (pySession) {
        lastSavedDesktopPath = await window.pywebview.api.finish_save_session(pySession.session_id);
      }

      const finalBlob = (!pySession || totalLen <= 50 * 1024 * 1024)
        ? new Blob(decryptedChunks)
        : new Blob([]);
      lastResultBlob = finalBlob;
      currentDecryptedPlaintext = decryptedChunks;

      progressFill.style.width = '100%';
      progressPct.textContent = '100%';
      progressStatus.textContent = 'Complete!';

      const elapsedMs = performance.now() - startTime;
      const speedMBps = ((finalBlob.size / (1024 * 1024)) / (elapsedMs / 1000)).toFixed(2);
      document.getElementById('vault-speed-lbl').textContent = `⚡ Speed: ${speedMBps} MB/s`;
      document.getElementById('vault-chunks-lbl').textContent = `📦 Chunks: ${chunkIndex}`;

      showCryptoSuccess('Decryption Complete!', `All authentication tags valid (${formatBytes(finalBlob.size)}).`, lastResultFilename, true);
      playSFX('unlock');
      logLocalAuditEvent('DECRYPT_SUCCESS', currentUser ? currentUser.username : 'User', `Decrypted '${selectedFile.name}'`);
    }
  } catch (err) {
    if (pySession && window.pywebview && window.pywebview.api) {
      try { await window.pywebview.api.cancel_save_session(pySession.session_id); } catch (ce) {}
    }
    playSFX('error');
    progressBox.classList.add('hidden');
    alert(`Crypto Operation Failed:\n\n${err.message}`);
  } finally {
    isProcessingCrypto = false;
    btn.disabled = false;
  }
}

function showCryptoSuccess(title, desc, filename, allowPreview) {
  const resultBox = document.getElementById('vault-result-box');
  document.getElementById('result-title').textContent = title;

  if (lastSavedDesktopPath) {
    document.getElementById('result-desc').textContent = `${desc}\nSaved directly to: ${lastSavedDesktopPath}`;
  } else {
    document.getElementById('result-desc').textContent = `${desc} Click Download to save to your local folder.`;
  }
  document.getElementById('download-filename').textContent = filename;

  const downloadBtn = document.getElementById('btn-download-result');
  const url = URL.createObjectURL(lastResultBlob);
  downloadBtn.href = url;
  downloadBtn.download = filename;
  downloadBtn.onclick = (e) => {
    if (window.pywebview && window.pywebview.api) {
      e.preventDefault();
      saveResultToDesktop();
    }
  };

  const previewBtn = document.getElementById('btn-preview-plaintext');
  if (allowPreview) {
    previewBtn.classList.remove('hidden');
  } else {
    previewBtn.classList.add('hidden');
  }

  resultBox.classList.remove('hidden');

  if (lastSavedDesktopPath) {
    playSFX('success');
    alert(`🎉 File Successfully Processed & Saved!\n\nLocation:\n${lastSavedDesktopPath}`);
  } else {
    setTimeout(() => {
      if (!window.pywebview) {
        downloadBtn.click();
      }
    }, 0);
  }
}

async function saveResultToDesktop() {
  if (lastSavedDesktopPath) {
    alert(`File is already safely stored on your Desktop at:\n${lastSavedDesktopPath}`);
    return;
  }
  if (!lastResultBlob || !lastResultFilename) return;

  try {
    if (window.pywebview && window.pywebview.api) {
      const session = await window.pywebview.api.start_save_session(lastResultFilename);
      const totalSize = lastResultBlob.size;
      const sliceSize = 1024 * 1024; // 1 MB slices
      let offset = 0;
      while (offset < totalSize) {
        const slice = lastResultBlob.slice(offset, Math.min(offset + sliceSize, totalSize));
        const buf = await slice.arrayBuffer();
        const b64 = bytesToBase64(new Uint8Array(buf));
        await window.pywebview.api.append_chunk(session.session_id, b64);
        offset += slice.size;
      }
      lastSavedDesktopPath = await window.pywebview.api.finish_save_session(session.session_id);
      playSFX('success');
      alert(`File saved on your Desktop:\n${lastSavedDesktopPath}`);
      return;
    }

    if (window.showSaveFilePicker) {
      const handle = await window.showSaveFilePicker({
        suggestedName: lastResultFilename,
        types: [{
          description: 'Aegis Vault File',
          accept: { 'application/octet-stream': [lastResultFilename.endsWith('.vault') ? '.vault' : '.*'] }
        }]
      });
      const writable = await handle.createWritable();
      await writable.write(lastResultBlob);
      await writable.close();
      playSFX('success');
      alert(`File saved successfully as ${lastResultFilename}.`);
      return;
    }

    const url = URL.createObjectURL(lastResultBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = lastResultFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    playSFX('success');
  } catch (err) {
    if (err.name !== 'AbortError') {
      alert(`Unable to save the file: ${err.message}`);
    }
  }
}

// Derive PBKDF2 Key
async function deriveKeyFromPassword(password, salt, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Chunk Nonce computation (96-bit nonce + 64-bit index)
function computeChunkNonce(baseNonce, chunkIndex) {
  const nonce = new Uint8Array(12);
  nonce.set(baseNonce);
  // XOR chunk index into the lower 8 bytes (big-endian), matching Python crypto_engine
  const dv = new DataView(nonce.buffer, 4, 8);
  const baseLow = dv.getUint32(4, false);
  dv.setUint32(4, (baseLow ^ chunkIndex) >>> 0, false);
  return nonce;
}

// ============================================================================
// TAB 2: ENCRYPTED SAFE (LOCAL LOCKER WITH INDEXEDDB FILE STORAGE)
// ============================================================================

const SAFE_DB_NAME = 'AegisSafeDB';
const SAFE_STORE_NAME = 'safe_blobs';

function getSafeDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(SAFE_DB_NAME, 1);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(SAFE_STORE_NAME)) {
        db.createObjectStore(SAFE_STORE_NAME, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function storeSafeFile(id, blob) {
  try {
    const db = await getSafeDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(SAFE_STORE_NAME, 'readwrite');
      tx.objectStore(SAFE_STORE_NAME).put({ id, blob });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    console.warn('IndexedDB safe file storage error:', e);
  }
}

async function getSafeFile(id) {
  try {
    const db = await getSafeDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(SAFE_STORE_NAME, 'readonly');
      const req = tx.objectStore(SAFE_STORE_NAME).get(id);
      req.onsuccess = () => resolve(req.result ? req.result.blob : null);
      req.onerror = () => reject(req.error);
    });
  } catch (e) {
    console.warn('IndexedDB safe file retrieval error:', e);
    return null;
  }
}

async function removeSafeFile(id) {
  try {
    const db = await getSafeDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(SAFE_STORE_NAME, 'readwrite');
      tx.objectStore(SAFE_STORE_NAME).delete(id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (e) {
    console.warn('IndexedDB safe file removal error:', e);
  }
}

async function saveCurrentResultToSafe() {
  if (!lastResultBlob || !lastResultFilename) return;

  const item = {
    id: 'safe_' + Date.now(),
    name: lastResultFilename,
    size: lastResultBlob.size,
    timestamp: new Date().toISOString(),
    tag: lastResultFilename.endsWith('.vault') ? 'Encrypted' : 'Plaintext'
  };

  await storeSafeFile(item.id, lastResultBlob);
  localSafeItems.unshift(item);
  localStorage.setItem('aegis_safe_items', JSON.stringify(localSafeItems));
  updateSafeCountBadge();
  playSFX('success');
  alert(`'${lastResultFilename}' has been safely stored in your Encrypted Safe!`);
}

function updateSafeCountBadge() {
  const badge = document.getElementById('safe-count-badge');
  if (badge) badge.textContent = localSafeItems.length;
}

function renderSafeItems(filterText = '') {
  const container = document.getElementById('safe-items-container');
  if (!container) return;

  const items = filterText
    ? localSafeItems.filter(i => i.name.toLowerCase().includes(filterText.toLowerCase()))
    : localSafeItems;

  if (items.length === 0) {
    container.innerHTML = `
      <div class="text-center text-muted" style="grid-column: 1 / -1; padding: 2.5rem;">
        <span style="font-size: 2.5rem; display: block; margin-bottom: 0.5rem;">📁</span>
        No items in your Encrypted Safe. Encrypt files in Vault Studio to store them here.
      </div>
    `;
    return;
  }

  container.innerHTML = items.map(item => `
    <div class="safe-card">
      <div class="safe-card-header">
        <span style="font-size: 1.5rem;">${item.name.endsWith('.vault') ? '🔒' : '📄'}</span>
        <div>
          <div class="safe-card-title">${escapeHtml(item.name)}</div>
          <div class="safe-card-meta">${formatBytes(item.size)} • ${item.timestamp.substring(0, 10)}</div>
        </div>
      </div>
      <div class="safe-card-actions">
        <button type="button" class="btn btn-secondary btn-sm" onclick="downloadSafeItem('${item.id}', '${escapeHtml(item.name)}')">⬇️ Download</button>
        <button type="button" class="btn btn-danger btn-sm" onclick="deleteSafeItem('${item.id}')">🗑️ Delete</button>
      </div>
    </div>
  `).join('');
}

function filterSafeItems() {
  const val = document.getElementById('safe-search-input').value;
  renderSafeItems(val);
}

async function downloadSafeItem(id, name) {
  let blob = null;
  if (lastResultBlob && lastResultFilename === name) {
    blob = lastResultBlob;
  } else {
    blob = await getSafeFile(id);
  }

  if (blob) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    playSFX('success');
  } else {
    alert(`File reference '${name}' is stored locally. Re-select the file in Vault Studio to decrypt.`);
  }
}

async function deleteSafeItem(id) {
  playSFX('click');
  await removeSafeFile(id);
  localSafeItems = localSafeItems.filter(i => i.id !== id);
  localStorage.setItem('aegis_safe_items', JSON.stringify(localSafeItems));
  updateSafeCountBadge();
  renderSafeItems();
}

function exportSafeManifest() {
  const data = JSON.stringify(localSafeItems, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'aegis_safe_manifest.json';
  a.click();
  playSFX('success');
}

function importSafeManifest(files) {
  if (!files || files.length === 0) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const items = JSON.parse(reader.result);
      if (Array.isArray(items)) {
        localSafeItems = items;
        localStorage.setItem('aegis_safe_items', JSON.stringify(localSafeItems));
        updateSafeCountBadge();
        renderSafeItems();
        playSFX('success');
      }
    } catch (e) {
      alert('Invalid safe manifest file.');
    }
  };
  reader.readAsText(files[0]);
}

// ============================================================================
// TAB 3: SECV BINARY HEADER INSPECTOR
// ============================================================================

function inspectVaultHeader(files) {
  if (!files || files.length === 0) return;
  playSFX('click');
  const file = files[0];
  const reader = new FileReader();
  reader.onload = () => {
    const bytes = new Uint8Array(reader.result);
    const resultBox = document.getElementById('inspector-result-box');
    const grid = document.getElementById('inspector-fields-grid');

    if (bytes.length < 37) {
      alert('File too short to contain a valid SECV header.');
      return;
    }

    const magic = String.fromCharCode(...bytes.slice(0, 4));
    const version = bytes[4];
    const dv = new DataView(bytes.buffer, 5, 4);
    const chunkSize = dv.getUint32(0, false);
    const saltHex = bytesToHex(bytes.slice(9, 25));
    const nonceHex = bytesToHex(bytes.slice(25, 37));
    const isMagicValid = (magic === 'SECV');

    grid.innerHTML = `
      <div class="inspector-field">
        <div class="inspector-key">Magic Identifier</div>
        <div class="inspector-val font-bold ${isMagicValid ? 'text-accent' : 'text-danger'}">${magic} (${isMagicValid ? '0x53454356 Valid' : 'Invalid'})</div>
      </div>
      <div class="inspector-field">
        <div class="inspector-key">Format Version</div>
        <div class="inspector-val font-bold text-cyan">0x0${version} (Standard SECV v1)</div>
      </div>
      <div class="inspector-field">
        <div class="inspector-key">Chunk Size</div>
        <div class="inspector-val">${chunkSize / 1024} KB (${chunkSize} Bytes)</div>
      </div>
      <div class="inspector-field">
        <div class="inspector-key">CSPRNG Salt (128-bit)</div>
        <div class="inspector-val text-small">${saltHex}</div>
      </div>
      <div class="inspector-field">
        <div class="inspector-key">Base Nonce (96-bit)</div>
        <div class="inspector-val text-small">${nonceHex}</div>
      </div>
      <div class="inspector-field">
        <div class="inspector-key">Total File Size</div>
        <div class="inspector-val">${formatBytes(file.size)} (~${Math.ceil((file.size - 37) / (chunkSize + 16))} Chunks)</div>
      </div>
    `;

    resultBox.classList.remove('hidden');
    playSFX('success');
  };
  reader.readAsArrayBuffer(file.slice(0, 64));
}

// ============================================================================
// TAB 4: PASSPHRASE FORTRESS & GENERATOR
// ============================================================================

let generatorMode = 'random'; // 'random' or 'diceware'

const DICEWARE_WORDLIST = [
  "shield", "cipher", "matrix", "beacon", "vector", "galaxy", "tunnel", "zenith",
  "shadow", "falcon", "crypto", "anchor", "silver", "atomic", "dragon", "forest",
  "signal", "planet", "plasma", "meteor", "nebula", "vortex", "quantum", "oracle",
  "titan", "hydra", "cosmic", "aurora", "blaze", "storm", "ember", "frost",
  "stone", "river", "ocean", "lunar", "solar", "steel", "flame", "prism",
  "nexus", "pulse", "drift", "surge", "spark", "glyph", "raven", "hawk",
  "eagle", "cobra", "alpha", "bravo", "delta", "gamma", "omega", "sigma",
  "theta", "zephyr", "anvil", "crown", "guard", "haven", "ivory", "jade",
  "karma", "latch", "maple", "noble", "onyx", "pearl", "quartz", "ruby",
  "saber", "topaz", "ultra", "vigor", "waltz", "xenon", "yacht", "zinc",
  "arrow", "blade", "cliff", "dawn", "echo", "flock", "grove", "haze",
  "jewel", "knot", "lemon", "mango", "north", "oasis", "palm", "quest",
  "ridge", "swift", "torch", "unity", "valve", "wheat", "apex", "bolt",
  "crest", "dusk", "fern", "globe", "halo", "index", "jolt", "kite",
  "lance", "marsh", "nerve", "optic", "plume", "quill", "relay", "scope",
  "thorn", "urban", "vault", "wired", "axiom", "youth", "zone", "bridge",
  "castle", "dagger", "engine", "flare", "gadget", "harbor", "impact", "jungle",
  "kindle", "legend", "mirror", "needle", "origin", "patrol", "ripple", "scarlet",
  "temple", "vivid", "whisper", "yonder", "zodiac", "binary", "chrome", "decode",
  "enigma", "fabric", "genome", "hybrid", "ignite", "jigsaw", "neural", "offset",
  "photon", "radial", "static", "turbo", "uplink", "vertex", "warden", "cobalt",
  "dynamo", "eclipse", "fusion", "granite", "helium", "indigo", "jasper", "krypton",
  "lambda", "magnet", "nether", "piston", "quasar", "rocket", "sphinx", "tundra",
  "umbra", "venom", "wraith", "argon", "basalt", "carbon", "flint", "gilded",
  "hollow", "kelvin", "lynx", "molten", "neon", "oxide", "pyrite", "rogue",
  "slate", "umber", "vapor", "acorn", "birch", "cedar", "fjord", "glen",
  "heath", "inlet", "lotus", "mesa", "novel", "olive", "peak", "reef",
  "shoal", "trail", "vine", "whale", "aspen", "brook", "coral", "gorge",
  "kayak", "polar", "shelf", "cove", "gale", "mist", "sage", "tide",
  "wren", "bass", "cope", "dock", "edge", "flux", "grip", "helm",
  "iris", "jazz", "keen", "link", "mode", "port", "rank", "scan",
  "task", "unit", "wave", "axis", "byte", "chip", "core", "grid"
];

function setGeneratorMode(mode) {
  generatorMode = mode;
  playSFX('click');
  const btnRand = document.getElementById('btn-gen-mode-random');
  const btnDice = document.getElementById('btn-gen-mode-diceware');
  const ctrlRand = document.getElementById('gen-controls-random');
  const ctrlDice = document.getElementById('gen-controls-diceware');

  if (mode === 'random') {
    btnRand.classList.add('active');
    btnDice.classList.remove('active');
    ctrlRand.classList.remove('hidden');
    ctrlDice.classList.add('hidden');
  } else {
    btnDice.classList.add('active');
    btnRand.classList.remove('active');
    ctrlDice.classList.remove('hidden');
    ctrlRand.classList.add('hidden');
  }
  generateFortressPassphrase();
}

function updateGeneratorLength(val) {
  document.getElementById('gen-length-val').textContent = val;
  generateFortressPassphrase();
}

function updateGeneratorWords(val) {
  document.getElementById('gen-words-val').textContent = val;
  generateFortressPassphrase();
}

function generateFortressPassphrase() {
  const display = document.getElementById('generated-passphrase-display');
  if (!display) return;

  let pwd = '';
  let entropy = 0;

  if (generatorMode === 'random') {
    const len = parseInt(document.getElementById('gen-length-slider').value, 10);
    const useUpper = document.getElementById('chk-uppercase').checked;
    const useLower = document.getElementById('chk-lowercase').checked;
    const useDigits = document.getElementById('chk-numbers').checked;
    const useSymbols = document.getElementById('chk-symbols').checked;

    let pool = '';
    if (useUpper) pool += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    if (useLower) pool += 'abcdefghijkmnopqrstuvwxyz';
    if (useDigits) pool += '23456789';
    if (useSymbols) pool += '!@#$%^&*()-_=+[]{}|;:,.<>?';

    if (!pool) pool = 'abcdefghijklmnopqrstuvwxyz';

    const randArr = new Uint32Array(len);
    crypto.getRandomValues(randArr);
    for (let i = 0; i < len; i++) {
      pwd += pool[randArr[i] % pool.length];
    }
    entropy = len * Math.log2(pool.length);
  } else {
    const wordsCount = parseInt(document.getElementById('gen-words-slider').value, 10);
    const randArr = new Uint32Array(wordsCount);
    crypto.getRandomValues(randArr);
    const chosen = [];
    for (let i = 0; i < wordsCount; i++) {
      chosen.push(DICEWARE_WORDLIST[randArr[i] % DICEWARE_WORDLIST.length]);
    }
    pwd = chosen.join('-');
    entropy = wordsCount * Math.log2(DICEWARE_WORDLIST.length);
  }

  display.textContent = pwd;
  updateEntropyDisplay(entropy);
}

function updateEntropyDisplay(bits) {
  const valEl = document.getElementById('entropy-bits-val');
  const bar = document.getElementById('fortress-strength-bar');
  const txt = document.getElementById('fortress-rating-text');

  valEl.textContent = `${bits.toFixed(1)} Bits`;
  const pct = Math.min(100, (bits / 128) * 100);
  bar.style.width = `${pct}%`;

  if (bits < 50) {
    bar.style.background = 'var(--danger)';
    txt.textContent = 'Weak Entropy • Vulnerable to Brute Force';
    txt.className = 'text-small text-danger';
  } else if (bits < 80) {
    bar.style.background = 'var(--warning)';
    txt.textContent = 'Moderate Entropy • Standard Protection';
    txt.className = 'text-small';
    txt.style.color = 'var(--warning)';
  } else {
    bar.style.background = 'var(--accent)';
    txt.textContent = 'NIST SP 800-63B Compliant • Military Grade';
    txt.className = 'text-small text-accent';
  }
}

function copyGeneratedPassphrase() {
  const text = document.getElementById('generated-passphrase-display').textContent;
  if (text) {
    navigator.clipboard.writeText(text);
    playSFX('success');
  }
}

// ============================================================================
// TAB 6: SECURITY AUDIT & TELEMETRY
// ============================================================================

async function loadAuditLogs() {
  const tbody = document.getElementById('audit-logs-body');
  try {
    const res = await fetch(`${API_BASE}/api/auth/audit`, {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });

    if (res.ok) {
      const data = await res.json();
      if (data.events && data.events.length > 0) {
        renderAuditRows(data.events);
        return;
      }
    }
  } catch (err) {}

  // Fallback to local session audit
  renderAuditRows(localAuditEvents);
}

function renderAuditRows(events) {
  const tbody = document.getElementById('audit-logs-body');
  if (!tbody) return;

  const filtered = (activeAuditFilter === 'ALL')
    ? events
    : events.filter(e => {
        if (activeAuditFilter === 'AUTH') return e.type.includes('LOGIN') || e.type.includes('REGISTER');
        if (activeAuditFilter === 'CRYPTO') return e.type.includes('ENCRYPT') || e.type.includes('DECRYPT');
        if (activeAuditFilter === 'RESET') return e.type.includes('RESET') || e.type.includes('PASSWORD');
        if (activeAuditFilter === 'LOCKOUT') return e.type.includes('LOCK') || e.type.includes('UNAUTHORIZED');
        return true;
      });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted" style="padding: 2rem;">No matching security records.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(ev => `
    <tr>
      <td class="font-mono text-small text-muted">${formatTime(ev.timestamp)}</td>
      <td><span class="tag-event tag-${ev.type}">${ev.type}</span></td>
      <td class="font-mono text-small text-cyan">${escapeHtml(ev.username || '127.0.0.1')}</td>
      <td>${escapeHtml(ev.details || '')}</td>
    </tr>
  `).join('');
}

function filterAuditEvents(filter, btn) {
  activeAuditFilter = filter;
  playSFX('click');
  document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  loadAuditLogs();
}

function logLocalAuditEvent(type, username, details) {
  const entry = {
    timestamp: new Date().toISOString(),
    type: type,
    username: username || 'User',
    details: details || ''
  };
  localAuditEvents.unshift(entry);
  if (localAuditEvents.length > 100) localAuditEvents.pop();
  localStorage.setItem('aegis_local_audit', JSON.stringify(localAuditEvents));
}

function exportAuditLogsCsv() {
  let csv = 'Timestamp,Event,User,Details\n';
  localAuditEvents.forEach(e => {
    csv += `"${e.timestamp}","${e.type}","${e.username}","${e.details}"\n`;
  });
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `aegis_audit_${Date.now()}.csv`;
  a.click();
  playSFX('success');
}

// ============================================================================
// TAB 7: BENCHMARK LAB
// ============================================================================

async function runCryptoBenchmark() {
  playSFX('click');
  const btn = document.getElementById('btn-run-benchmark');
  const log = document.getElementById('benchmark-log');
  const pbkdfEl = document.getElementById('bench-pbkdf2-time');
  const aesEl = document.getElementById('bench-aes-throughput');
  const scoreEl = document.getElementById('bench-score');

  btn.disabled = true;
  log.innerHTML = '⚡ Initiating cryptographic benchmark suite...<br>';

  try {
    // 1. Test PBKDF2-HMAC-SHA256 (600K)
    log.innerHTML += '🔒 Benchmarking PBKDF2 (600,000 Iterations)...<br>';
    const startPbkdf = performance.now();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    await deriveKeyFromPassword('BenchmarkSecretPassphrase2026!', salt, 600000);
    const pbkdfDuration = Math.round(performance.now() - startPbkdf);
    pbkdfEl.textContent = `${pbkdfDuration} ms`;
    log.innerHTML += `✅ PBKDF2 600K Latency: ${pbkdfDuration} ms<br>`;

    // 2. Test AES-256-GCM Streaming Throughput (5 MB)
    log.innerHTML += '📦 Benchmarking AES-256-GCM Throughput (5 MB Payload)...<br>';
    const testSize = 5 * 1024 * 1024;
    const testData = new Uint8Array(testSize);
    crypto.getRandomValues(testData.slice(0, 1024)); // Seed partial

    const key = await deriveKeyFromPassword('quickKey', salt, 1000);
    const startAes = performance.now();

    const chunkSize = 64 * 1024;
    let offset = 0;
    let chunkIdx = 0;
    while (offset < testSize) {
      const chunk = testData.slice(offset, offset + chunkSize);
      const iv = computeChunkNonce(new Uint8Array(12), chunkIdx);
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, chunk);
      offset += chunkSize;
      chunkIdx++;
    }

    const aesDurationSec = (performance.now() - startAes) / 1000;
    const throughput = ((testSize / (1024 * 1024)) / aesDurationSec).toFixed(1);
    aesEl.textContent = `${throughput} MB/s`;
    log.innerHTML += `✅ AES-256-GCM Streaming Speed: ${throughput} MB/s<br>`;

    // Composite Score
    const score = Math.round((parseFloat(throughput) * 10) + (10000 / Math.max(50, pbkdfDuration)));
    scoreEl.textContent = `${score} PTS`;
    log.innerHTML += `🏆 Benchmark Completed! Index Score: <strong>${score} PTS</strong><br>`;
    playSFX('success');
  } catch (err) {
    log.innerHTML += `❌ Error during benchmark: ${err.message}<br>`;
  } finally {
    btn.disabled = false;
  }
}

// ============================================================================
// PROCEDURAL SYNTH SOUND ENGINE (WEB AUDIO API)
// ============================================================================

let audioCtx = null;

function initSFX() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (AudioContext) {
      audioCtx = new AudioContext();
    }
  } catch (e) {}
}

function toggleSFX() {
  sfxEnabled = !sfxEnabled;
  localStorage.setItem('aegis_sfx', sfxEnabled);
  updateSFXButton();
  if (sfxEnabled) playSFX('click');
}

function updateSFXButton() {
  const icon = document.getElementById('sfx-icon');
  const text = document.getElementById('sfx-text');
  const btn = document.getElementById('btn-sfx-toggle');
  if (sfxEnabled) {
    if (icon) icon.textContent = '🔊';
    if (text) text.textContent = 'SFX On';
    if (btn) btn.classList.add('header-action-btn--active');
  } else {
    if (icon) icon.textContent = '🔇';
    if (text) text.textContent = 'SFX Muted';
    if (btn) btn.classList.remove('header-action-btn--active');
  }
}

function playSFX(type) {
  if (!sfxEnabled || !audioCtx) return;
  if (audioCtx.state === 'suspended') {
    audioCtx.resume();
  }

  try {
    const now = audioCtx.currentTime;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (type === 'click') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(600, now);
      osc.frequency.exponentialRampToValueAtTime(300, now + 0.04);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.04);
      osc.start(now);
      osc.stop(now + 0.04);
    } else if (type === 'lock') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(320, now);
      osc.frequency.exponentialRampToValueAtTime(640, now + 0.12);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
      osc.start(now);
      osc.stop(now + 0.12);
    } else if (type === 'unlock') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(640, now);
      osc.frequency.exponentialRampToValueAtTime(320, now + 0.12);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
      osc.start(now);
      osc.stop(now + 0.12);
    } else if (type === 'success') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.setValueAtTime(660, now + 0.08);
      osc.frequency.setValueAtTime(880, now + 0.16);
      gain.gain.setValueAtTime(0.1, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
      osc.start(now);
      osc.stop(now + 0.25);
    } else if (type === 'error') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(220, now);
      osc.frequency.setValueAtTime(160, now + 0.1);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      osc.start(now);
      osc.stop(now + 0.2);
    }
  } catch (e) {}
}

// ============================================================================
// MODALS & SHORTCUTS
// ============================================================================

function openShortcutsModal() {
  playSFX('click');
  document.getElementById('shortcuts-modal').classList.remove('hidden');
}

function closeShortcutsModal() {
  document.getElementById('shortcuts-modal').classList.add('hidden');
}

function openChangePasswordModal() {
  playSFX('click');
  document.getElementById('profile-dropdown-menu').classList.add('hidden');
  document.getElementById('pwd-modal').classList.remove('hidden');
}

function closeChangePasswordModal() {
  document.getElementById('pwd-modal').classList.add('hidden');
  document.getElementById('modal-feedback').className = 'alert-box hidden';
}

async function handleChangePassword(e) {
  e.preventDefault();
  playSFX('click');
  const currentPassword = document.getElementById('current-password').value;
  const newPassword = document.getElementById('new-password').value;
  const feedback = document.getElementById('modal-feedback');

  if (newPassword && newPassword.length > 128) {
    playSFX('error');
    showAlert(feedback, 'error', 'Password must not exceed 128 characters.');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/auth/change-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`
      },
      body: JSON.stringify({ currentPassword, newPassword })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      playSFX('success');
      showAlert(feedback, 'success', 'Password updated successfully!');
      setTimeout(closeChangePasswordModal, 1200);
    } else {
      playSFX('error');
      showAlert(feedback, 'error', data.error || 'Failed to update password.');
    }
  } catch (err) {
    playSFX('error');
    showAlert(feedback, 'error', 'Password change server is unavailable. Please start the Aegis security node and try again.');
  }
}

function previewPlaintextResult() {
  if (!currentDecryptedPlaintext) return;
  playSFX('click');

  const modal = document.getElementById('preview-modal');
  const body = document.getElementById('preview-modal-body');

  const totalLen = currentDecryptedPlaintext.reduce((acc, c) => acc + c.length, 0);
  const merged = new Uint8Array(totalLen);
  let pos = 0;
  currentDecryptedPlaintext.forEach(c => {
    merged.set(c, pos);
    pos += c.length;
  });

  const ext = lastResultFilename.split('.').pop().toLowerCase();

  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext)) {
    const blob = new Blob([merged]);
    const url = URL.createObjectURL(blob);
    body.innerHTML = `<div class="text-center"><img src="${url}" style="max-width: 100%; border-radius: 8px;"></div>`;
  } else {
    // Try text decoding
    try {
      const dec = new TextDecoder('utf-8', { fatal: true });
      const text = dec.decode(merged.slice(0, 50000));
      body.innerHTML = `<pre class="font-mono text-small" style="background: #040810; padding: 1rem; border-radius: 8px; color: var(--cyan); white-space: pre-wrap;">${escapeHtml(text)}</pre>`;
    } catch (e) {
      body.innerHTML = `<div class="text-muted font-mono text-small">Binary file decoded (${formatBytes(totalLen)}). Hex preview not rendered.</div>`;
    }
  }

  modal.classList.remove('hidden');
}

function closePreviewModal() {
  document.getElementById('preview-modal').classList.add('hidden');
}

function handleGlobalKeydown(e) {
  if (e.key === 'Escape') {
    closeShortcutsModal();
    closeChangePasswordModal();
    closePreviewModal();
    const dd = document.getElementById('profile-dropdown-menu');
    if (dd) dd.classList.add('hidden');
    return;
  }

  if (e.ctrlKey) {
    if (e.key === 'e' || e.key === 'E') {
      e.preventDefault();
      switchNavTab('vault-studio');
      setVaultStudioMode('encrypt');
    } else if (e.key === 'd' || e.key === 'D') {
      e.preventDefault();
      switchNavTab('vault-studio');
      setVaultStudioMode('decrypt');
    } else if (e.key === 's' || e.key === 'S') {
      e.preventDefault();
      switchNavTab('encrypted-safe');
    } else if (e.key === 'g' || e.key === 'G') {
      e.preventDefault();
      switchNavTab('passphrase-fortress');
    } else if (e.key === 'i' || e.key === 'I') {
      e.preventDefault();
      switchNavTab('identity-auth');
    } else if (e.key === 'b' || e.key === 'B') {
      e.preventDefault();
      switchNavTab('benchmark-lab');
    }
  }
}

// ============================================================================
// UTILITIES
// ============================================================================

function togglePasswordVisibility(id) {
  const el = document.getElementById(id);
  if (el) el.type = el.type === 'password' ? 'text' : 'password';
}

function evaluateStrength(pwd) {
  const bar = document.getElementById('strength-bar');
  const txt = document.getElementById('strength-text');
  if (!pwd) {
    bar.style.width = '0%';
    txt.textContent = 'Password complexity: None';
    txt.style.color = 'var(--text-muted)';
    return;
  }
  let score = 0;
  if (pwd.length >= 8) score += 25;
  if (pwd.length >= 14) score += 15;
  if (/[A-Z]/.test(pwd)) score += 20;
  if (/[a-z]/.test(pwd)) score += 15;
  if (/[0-9]/.test(pwd)) score += 15;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) score += 10;

  bar.style.width = `${Math.min(100, score)}%`;
  if (score < 40) {
    bar.style.background = 'var(--danger)';
    txt.textContent = 'Password complexity: Weak';
    txt.style.color = 'var(--danger)';
  } else if (score < 75) {
    bar.style.background = 'var(--warning)';
    txt.textContent = 'Password complexity: Moderate';
    txt.style.color = 'var(--warning)';
  } else if (score < 90) {
    bar.style.background = 'var(--primary)';
    txt.textContent = 'Password complexity: Strong';
    txt.style.color = 'var(--primary)';
  } else {
    bar.style.background = 'var(--accent)';
    txt.textContent = 'Password complexity: Military-Grade 🛡️';
    txt.style.color = 'var(--accent)';
  }
}

function evaluateForgotStrength(pwd) {
  const bar = document.getElementById('forgot-strength-bar');
  if (!bar) return;
  const score = Math.min(100, (pwd.length * 10));
  bar.style.width = `${score}%`;
  bar.style.background = score > 70 ? 'var(--accent)' : 'var(--warning)';
}

function showAlert(box, type, msg) {
  box.className = `alert-box ${type}`;
  box.textContent = msg;
  box.classList.remove('hidden');
}

function clearAlerts() {
  document.querySelectorAll('.alert-box').forEach(b => b.classList.add('hidden'));
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatTime(iso) {
  if (!iso) return 'Just now';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return iso;
  }
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
}

function generateRandomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
