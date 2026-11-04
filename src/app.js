/**
 * ipVision 2.0 — Client Application
 * Features:
 * - Step 3: Neon letter-by-letter intro with sweeping tube light & keyboard shortcuts
 * - Step 4 & 5: Supabase Auth integration, single-active-session handling, scan history
 * - Scanner with clean view, opt-in distance estimation, and security indicators
 * - Step 11: Modernized interactive feedback widget
 */

// ---------------------------------------------------------------------------
// DOM Elements
// ---------------------------------------------------------------------------
const introOverlay = document.getElementById('intro-overlay');
const introHeadline = document.getElementById('intro-headline');
const skipIntroBtn = document.getElementById('skip-intro-btn');
const sweepBar = document.querySelector('.neon-tube-sweep');

const authModal = document.getElementById('auth-modal');
const authOpenBtn = document.getElementById('auth-open-btn');
const authCloseBtn = document.getElementById('auth-close-btn');
const authBtnLabel = document.getElementById('auth-btn-label');
const userMenu = document.getElementById('user-menu');
const logoutBtn = document.getElementById('logout-btn');
const authForm = document.getElementById('auth-form');
const authEmailInput = document.getElementById('auth-email');
const authPasswordInput = document.getElementById('auth-password');
const authStatus = document.getElementById('auth-status');
const authSubmitBtn = document.getElementById('auth-submit-btn');
const tabLogin = document.getElementById('tab-login');
const tabSignup = document.getElementById('tab-signup');
const authGateBanner = document.getElementById('auth-gate-banner');
const gateSigninBtn = document.getElementById('gate-signin-btn');

const historyDrawer = document.getElementById('history-drawer');
const historyOpenBtn = document.getElementById('history-open-btn');
const historyCloseBtn = document.getElementById('history-close-btn');
const historyList = document.getElementById('history-list');
const historyCount = document.getElementById('history-count');
const clearHistoryBtn = document.getElementById('clear-history-btn');
const saveScanBtn = document.getElementById('save-scan-btn');

const form = document.getElementById('scan-form');
const ipInput = document.getElementById('ip-input');
const scanButton = document.getElementById('submit-scan-btn');
const scanStatus = document.getElementById('scan-status');
const clearButton = document.getElementById('clear-input');
const cleanView = document.getElementById('clean-view');
const results = document.getElementById('results');
const newScanButton = document.getElementById('new-scan');

const distancePanel = document.getElementById('distance-panel');
const distanceValue = document.getElementById('distance-value');
const distanceStatus = document.getElementById('distance-status');
const measureButton = document.getElementById('measure-distance');
const routeLink = document.getElementById('route-link');

// ---------------------------------------------------------------------------
// Global State
// ---------------------------------------------------------------------------
let currentUser = null;
let currentScanData = null;
let targetCoordinates = null;
let authMode = 'login'; // 'login' | 'signup'
let introDismissed = false;

// ---------------------------------------------------------------------------
// Step 3: Intro Animation Controller
// ---------------------------------------------------------------------------
function initIntroAnimation() {
  const isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const wordElements = introHeadline.querySelectorAll('.neon-word');

  // Build individual letter spans
  let letterIndex = 0;
  const allCharSpans = [];

  wordElements.forEach((wordEl) => {
    const text = wordEl.getAttribute('data-word') || '';
    wordEl.innerHTML = '';
    for (const char of text) {
      const span = document.createElement('span');
      span.className = 'neon-char';
      span.textContent = char;
      wordEl.appendChild(span);
      allCharSpans.push(span);
    }
  });

  if (isReducedMotion) {
    allCharSpans.forEach((span) => span.classList.add('is-lit'));
    window.setTimeout(dismissIntro, 800);
    return;
  }

  // Neon letter-by-letter activation
  const totalLetters = allCharSpans.length;
  const intervalMs = Math.max(15, Math.floor(1000 / totalLetters));

  const letterTimer = window.setInterval(() => {
    if (letterIndex < totalLetters) {
      allCharSpans[letterIndex].classList.add('is-lit');
      letterIndex++;
    } else {
      window.clearInterval(letterTimer);
      // Trigger horizontal tube light sweep
      if (sweepBar) sweepBar.classList.add('is-active');
      // Fade out after sweep (total ~2 seconds)
      window.setTimeout(dismissIntro, 950);
    }
  }, intervalMs);

  function handleKeydown(e) {
    if (e.key === 'Escape' || e.key === 'Enter') {
      window.clearInterval(letterTimer);
      dismissIntro();
    }
  }

  window.addEventListener('keydown', handleKeydown, { once: true });
  skipIntroBtn.addEventListener('click', () => {
    window.clearInterval(letterTimer);
    dismissIntro();
  });
}

function dismissIntro() {
  if (introDismissed) return;
  introDismissed = true;
  introOverlay.classList.add('is-finished');
  window.setTimeout(() => {
    introOverlay.hidden = true;
  }, 400);
}

// ---------------------------------------------------------------------------
// IP Address Validation
// ---------------------------------------------------------------------------
function isValidIPv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function isValidIPv6(value) {
  if (!value || value.includes('%') || !/^[0-9a-f:.]+$/i.test(value)) return false;
  if (value.includes(':::')) return false;
  const compressed = value.split('::');
  if (compressed.length > 2) return false;

  let groups = [];
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const tail = value.slice(lastColon + 1);
    if (!isValidIPv4(tail)) return false;
    const octets = tail.split('.').map(Number);
    const g1 = ((octets[0] << 8) | octets[1]).toString(16);
    const g2 = ((octets[2] << 8) | octets[3]).toString(16);
    const head = value.slice(0, lastColon);
    groups = [...(head ? head.split(':') : []), g1, g2];
  } else {
    groups = value.split(':');
  }

  if (groups.some((g) => g !== '' && !/^[0-9a-f]{1,4}$/i.test(g))) return false;
  const count = groups.filter(Boolean).length;
  return compressed.length === 2 ? count < 8 : count === 8;
}

function isValidIp(value) {
  return isValidIPv4(value) || isValidIPv6(value);
}

// ---------------------------------------------------------------------------
// Step 4 & 5: Authentication & Single-Session Enforcement
// ---------------------------------------------------------------------------
async function checkAuthSession() {
  try {
    const res = await fetch('/api/auth/session');
    const data = await res.json();
    if (data.authenticated && data.user) {
      setAuthenticatedUser(data.user);
    } else {
      setUnauthenticatedUser();
    }
  } catch {
    setUnauthenticatedUser();
  }
}

function setAuthenticatedUser(user) {
  currentUser = user;
  authBtnLabel.textContent = user.email.split('@')[0];
  userMenu.hidden = false;
  authGateBanner.hidden = true;
  scanButton.disabled = false;
  fetchScanHistory();
}

function setUnauthenticatedUser() {
  currentUser = null;
  authBtnLabel.textContent = 'Sign In';
  userMenu.hidden = true;
  authGateBanner.hidden = false;
}

function handleSessionExpired(message) {
  setUnauthenticatedUser();
  alert(message || 'Your session has ended. Please sign in again.');
  openAuthModal('login');
}

function openAuthModal(mode = 'login') {
  authMode = mode;
  tabLogin.classList.toggle('is-active', mode === 'login');
  tabLogin.setAttribute('aria-selected', mode === 'login');
  tabSignup.classList.toggle('is-active', mode === 'signup');
  tabSignup.setAttribute('aria-selected', mode === 'signup');
  authSubmitBtn.querySelector('span').textContent = mode === 'login' ? 'Sign In' : 'Create Account';
  authStatus.textContent = '';
  authStatus.className = 'auth-status';
  authModal.hidden = false;
  authEmailInput.focus();
}

function closeAuthModal() {
  authModal.hidden = true;
  authForm.reset();
  authStatus.textContent = '';
}

tabLogin.addEventListener('click', () => openAuthModal('login'));
tabSignup.addEventListener('click', () => openAuthModal('signup'));
authOpenBtn.addEventListener('click', () => {
  if (currentUser) {
    openHistoryDrawer();
  } else {
    openAuthModal('login');
  }
});
gateSigninBtn.addEventListener('click', () => openAuthModal('signup'));
authCloseBtn.addEventListener('click', closeAuthModal);

authModal.addEventListener('click', (e) => {
  if (e.target === authModal) closeAuthModal();
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = authEmailInput.value.trim();
  const password = authPasswordInput.value;

  if (!email || !password) {
    authStatus.textContent = 'Please fill in both email and password.';
    authStatus.className = 'auth-status is-error';
    return;
  }
  if (password.length < 8) {
    authStatus.textContent = 'Password must be at least 8 characters long.';
    authStatus.className = 'auth-status is-error';
    return;
  }

  authSubmitBtn.disabled = true;
  authStatus.textContent = authMode === 'login' ? 'Verifying credentials…' : 'Creating secure account…';
  authStatus.className = 'auth-status';

  const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Authentication failed. Please check your credentials.');
    }

    setAuthenticatedUser(data.user);
    closeAuthModal();
  } catch (err) {
    authStatus.textContent = err.message;
    authStatus.className = 'auth-status is-error';
  } finally {
    authSubmitBtn.disabled = false;
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
  } finally {
    setUnauthenticatedUser();
    results.hidden = true;
  }
});

// ---------------------------------------------------------------------------
// Step 4: Scan History Drawer
// ---------------------------------------------------------------------------
function openHistoryDrawer() {
  historyDrawer.hidden = false;
  fetchScanHistory();
}
function closeHistoryDrawer() {
  historyDrawer.hidden = true;
}

historyOpenBtn.addEventListener('click', openHistoryDrawer);
historyCloseBtn.addEventListener('click', closeHistoryDrawer);
historyDrawer.addEventListener('click', (e) => {
  if (e.target === historyDrawer) closeHistoryDrawer();
});

async function fetchScanHistory() {
  if (!currentUser) return;
  try {
    const res = await fetch('/api/scans');
    if (res.status === 401) {
      const err = await res.json();
      if (err.error && err.error.includes('Another session')) {
        handleSessionExpired(err.error);
      }
      return;
    }
    const data = await res.json();
    renderHistoryList(data.scans || []);
  } catch {
    // Graceful fallback
  }
}

function renderHistoryList(scans) {
  historyCount.textContent = `${scans.length} Scan${scans.length === 1 ? '' : 's'} Recorded`;
  if (!scans.length) {
    historyList.innerHTML = '<p class="history-empty">No scans saved yet. Run an inspection and click "★ Save Scan" to record it.</p>';
    return;
  }
  historyList.innerHTML = scans.map((s) => `
    <div class="history-item">
      <div>
        <div class="history-ip">${s.ip}</div>
        <div class="history-geo">${s.city || 'Unknown'}, ${s.country || 'Unknown'} · ${s.timestamp}</div>
      </div>
      <button class="history-rescan-btn" data-ip="${s.ip}" type="button">Rescan</button>
    </div>
  `).join('');

  historyList.querySelectorAll('.history-rescan-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetIp = btn.getAttribute('data-ip');
      ipInput.value = targetIp;
      closeHistoryDrawer();
      executeScan(targetIp);
    });
  });
}

clearHistoryBtn.addEventListener('click', async () => {
  if (!confirm('Clear all saved scans from your history?')) return;
  try {
    await fetch('/api/scans', { method: 'DELETE' });
    renderHistoryList([]);
  } catch (err) {
    alert('Failed to clear history.');
  }
});

saveScanBtn.addEventListener('click', async () => {
  if (!currentUser) {
    openAuthModal('signup');
    return;
  }
  if (!currentScanData) return;

  saveScanBtn.disabled = true;
  saveScanBtn.textContent = 'Saving…';
  try {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip: currentScanData.ip || currentScanData.query,
        city: currentScanData.location?.city || 'Unknown',
        country: currentScanData.location?.country || 'Unknown',
        isp: currentScanData.connection?.isp || 'Unknown',
        risk: currentScanData.security?.proxy ? 'High (Proxy)' : 'Low',
      }),
    });
    if (res.status === 401) {
      const err = await res.json();
      if (err.error && err.error.includes('Another session')) {
        handleSessionExpired(err.error);
        return;
      }
    }
    saveScanBtn.textContent = '✓ Saved to History';
  } catch {
    saveScanBtn.textContent = 'Failed to Save';
  } finally {
    window.setTimeout(() => {
      saveScanBtn.disabled = false;
      saveScanBtn.textContent = '★ Save Scan';
    }, 2500);
  }
});

// ---------------------------------------------------------------------------
// Scanner Flow & Result Rendering
// ---------------------------------------------------------------------------
function setStatus(msg = '', kind = '') {
  scanStatus.textContent = msg;
  scanStatus.className = `scan-status${kind ? ` is-${kind}` : ''}`;
}

function safe(val, fallback = 'Not available') {
  return (val === null || val === undefined || val === '') ? fallback : String(val);
}

function formatCoordinates(lat, lon) {
  if (typeof lat !== 'number' || typeof lon !== 'number') return 'Not available';
  return `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`;
}

function setSignalRow(id, isFlagged) {
  const row = document.getElementById(id);
  if (!row) return;
  const strong = row.querySelector('strong');
  if (isFlagged === true) {
    strong.textContent = 'Flagged';
    row.className = 'security-row is-flagged';
  } else if (isFlagged === false) {
    strong.textContent = 'Clear';
    row.className = 'security-row is-clear';
  } else {
    strong.textContent = 'Unknown';
    row.className = 'security-row';
  }
}

function renderResult(data) {
  currentScanData = data;
  const ip = data.ip || data.query;
  const loc = data.location || {};
  const conn = data.connection || {};
  const sec = data.security || {};

  const lat = loc.latitude ?? data.lat;
  const lon = loc.longitude ?? data.lon;
  const hasCoords = Number.isFinite(lat) && Number.isFinite(lon);
  targetCoordinates = hasCoords ? { latitude: lat, longitude: lon } : null;

  // Reset Distance Panel
  distancePanel.hidden = !hasCoords;
  distanceValue.textContent = '—';
  routeLink.hidden = true;
  measureButton.disabled = false;
  measureButton.textContent = 'Measure from my location';

  document.getElementById('results-heading').textContent = ip;
  document.getElementById('result-type').textContent = `${data.type || 'IP'} REPORT`;
  const locationStr = [loc.city, loc.state, loc.country].filter(Boolean).join(', ') || 'Location unavailable';
  document.getElementById('result-location').textContent = locationStr;
  document.getElementById('location-place').textContent = locationStr;
  document.getElementById('result-postal').textContent = safe(loc.postal);
  document.getElementById('result-timezone').textContent = safe(loc.timezone || data.timezone?.id);
  document.getElementById('result-coordinates').textContent = formatCoordinates(lat, lon);

  document.getElementById('result-isp').textContent = safe(conn.isp);
  document.getElementById('result-organization').textContent = safe(conn.org);
  document.getElementById('result-asn').textContent = conn.asn ? `AS${conn.asn} (${safe(conn.isp)})` : 'Not available';
  document.getElementById('result-connection-type').textContent = safe(conn.type);
  document.getElementById('result-address-type').textContent = safe(data.type, 'IPv4');

  // Threat signals
  const isProxy = sec.proxy === true;
  const isHosting = sec.hosting === true;
  const isMobile = sec.mobile === true;

  setSignalRow('signal-proxy', isProxy);
  setSignalRow('signal-hosting', isHosting);
  setSignalRow('signal-mobile', isMobile);

  // Device Profile (Fix 4)
  const deviceProfileEl = document.getElementById('result-device-profile');
  if (deviceProfileEl) {
    deviceProfileEl.textContent = data.device_profile || (
      isProxy ? 'VPN / Proxy Exit Node' :
      isHosting ? 'Cloud Server / Data Center' :
      isMobile ? 'Mobile Phone / Cellular Device' :
      'Home Router / Residential Broadband'
    );
  }

  const secSummary = document.getElementById('security-summary');
  const secTitle = document.getElementById('security-title');
  const secCaption = document.getElementById('security-caption');

  if (isProxy || isHosting) {
    secSummary.classList.add('has-risk');
    secTitle.textContent = isProxy ? 'High Threat / VPN Proxy' : 'Hosting Datacenter IP';
    secCaption.textContent = isProxy ? 'Known anonymizer or commercial VPN exit.' : 'Traffic originates from a cloud or datacenter network.';
  } else {
    secSummary.classList.remove('has-risk');
    secTitle.textContent = 'No Threat Flags Detected';
    secCaption.textContent = 'Clean residential or standard broadband carrier.';
  }

  const mapLink = document.getElementById('map-link');
  if (hasCoords) {
    mapLink.href = `https://www.google.com/maps?q=${lat},${lon}`;
    mapLink.hidden = false;
  } else {
    mapLink.hidden = true;
  }

  results.hidden = false;
  applyCleanView();
  results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function applyCleanView() {
  const isClean = cleanView.checked;
  document.querySelectorAll('[data-private]').forEach((el) => {
    el.hidden = isClean;
  });
}
cleanView.addEventListener('change', applyCleanView);

async function executeScan(ip) {
  if (!currentUser) {
    openAuthModal('login');
    return;
  }

  if (ip && !isValidIp(ip)) {
    setStatus('Invalid IP address format. Enter a valid IPv4 or IPv6 address.', 'error');
    ipInput.setAttribute('aria-invalid', 'true');
    ipInput.focus();
    return;
  }

  ipInput.removeAttribute('aria-invalid');
  results.hidden = true;
  scanButton.disabled = true;
  setStatus('Establishing secure link & fetching carrier telemetry…', 'loading');

  const endpoint = ip ? `/api/lookup?ip=${encodeURIComponent(ip)}` : '/api/lookup';

  try {
    const res = await fetch(endpoint);
    const data = await res.json();

    if (res.status === 401) {
      if (data.requires_auth) {
        openAuthModal('login');
        setStatus('Please sign in to inspect IP addresses.', 'error');
        return;
      }
      if (data.error && data.error.includes('Another session')) {
        handleSessionExpired(data.error);
        return;
      }
    }

    if (!res.ok) {
      const errMsg = data.error || `Lookup error (${res.status})`;
      // Fix 1: Local dev hint for reserved range / private IP
      if (data.local_dev) {
        throw new Error('📡 ' + errMsg);
      }
      throw new Error(errMsg);
    }

    renderResult(data);
    setStatus('Scan completed successfully.', 'success');
  } catch (err) {
    setStatus(err.message || 'Lookup failed. Please try again.', 'error');
  } finally {
    scanButton.disabled = false;
  }
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  executeScan(ipInput.value.trim());
});

ipInput.addEventListener('input', () => {
  clearButton.hidden = !ipInput.value;
  setStatus();
});

clearButton.addEventListener('click', () => {
  ipInput.value = '';
  clearButton.hidden = true;
  ipInput.focus();
});

newScanButton.addEventListener('click', () => {
  ipInput.value = '';
  results.hidden = true;
  ipInput.focus();
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
});

// ---------------------------------------------------------------------------
// Distance Estimator
// ---------------------------------------------------------------------------
measureButton.addEventListener('click', () => {
  if (!targetCoordinates || !navigator.geolocation) {
    distanceStatus.textContent = 'Location service unavailable on this device.';
    return;
  }

  measureButton.disabled = true;
  measureButton.textContent = 'Requesting GPS…';
  distanceStatus.textContent = 'Waiting for your browser location permission…';

  navigator.geolocation.getCurrentPosition(
    (pos) => {
      const userLat = pos.coords.latitude;
      const userLon = pos.coords.longitude;
      const targetLat = targetCoordinates.latitude;
      const targetLon = targetCoordinates.longitude;

      // Haversine formula
      const R = 6371; // km
      const dLat = (targetLat - userLat) * (Math.PI / 180);
      const dLon = (targetLon - userLon) * (Math.PI / 180);
      const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(userLat * (Math.PI / 180)) * Math.cos(targetLat * (Math.PI / 180)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      const km = R * c;
      const miles = km * 0.621371;

      distanceValue.textContent = `~${km.toFixed(1)} km (${miles.toFixed(1)} mi)`;
      routeLink.href = `https://www.google.com/maps/dir/?api=1&origin=${userLat},${userLon}&destination=${targetLat},${targetLon}`;
      routeLink.hidden = false;
      distanceStatus.textContent = 'Straight-line estimate calculated in-browser.';
      measureButton.disabled = false;
      measureButton.textContent = 'Recalculate';
    },
    (err) => {
      distanceStatus.textContent = 'Location access was declined or timed out.';
      measureButton.disabled = false;
      measureButton.textContent = 'Try Again';
    },
    { timeout: 10000, enableHighAccuracy: false }
  );
});

// ---------------------------------------------------------------------------
// Step 11: Modernized Feedback Widget Controller
// ---------------------------------------------------------------------------
const feedbackForm = document.getElementById('feedback-form');
const feedbackMessage = document.getElementById('feedback-message');
const feedbackEmail = document.getElementById('feedback-email');
const feedbackToast = document.getElementById('feedback-toast');
const feedbackSubmitBtn = document.getElementById('feedback-submit-btn');
const charCount = document.getElementById('char-count');
const categoryPills = document.querySelectorAll('.category-pill');

let activeCategory = 'General';

categoryPills.forEach((pill) => {
  pill.addEventListener('click', () => {
    categoryPills.forEach((p) => p.classList.remove('is-active'));
    pill.classList.add('is-active');
    activeCategory = pill.getAttribute('data-cat') || 'General';
  });
});

feedbackMessage.addEventListener('input', () => {
  const len = feedbackMessage.value.length;
  charCount.textContent = `${len} / 1000`;
  if (len > 1000) {
    charCount.style.color = '#ff9b86';
  } else {
    charCount.style.color = '#9cb2aa';
  }
});

feedbackForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const message = feedbackMessage.value.trim();
  const email = feedbackEmail.value.trim();
  const sentimentRadio = document.querySelector('input[name="sentiment"]:checked');
  const sentiment = sentimentRadio ? sentimentRadio.value : 'good';

  if (message.length < 3) {
    feedbackToast.textContent = 'Please type at least a few words of feedback.';
    feedbackToast.className = 'feedback-toast is-error';
    feedbackMessage.focus();
    return;
  }

  feedbackSubmitBtn.disabled = true;
  feedbackToast.textContent = 'Transmitting feedback…';
  feedbackToast.className = 'feedback-toast';

  try {
    const res = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sentiment,
        category: activeCategory,
        message,
        reply_email: email,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Failed to submit feedback.');
    }

    feedbackToast.textContent = '✓ Thank you! Your thoughts have reached the team.';
    feedbackToast.className = 'feedback-toast is-success';
    feedbackForm.reset();
    charCount.textContent = '0 / 1000';
  } catch (err) {
    feedbackToast.textContent = err.message || 'Transmission error. Please try again.';
    feedbackToast.className = 'feedback-toast is-error';
  } finally {
    feedbackSubmitBtn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initIntroAnimation();
  checkAuthSession();
  applyCleanView();
});
