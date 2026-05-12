const emailInput   = document.getElementById('emailInput');
const analyzeBtn   = document.getElementById('analyzeBtn');
const resultCard   = document.getElementById('resultCard');
const gaugeArc     = document.getElementById('gaugeArc');
const gaugeScore   = document.getElementById('gaugeScore');
const riskBadge    = document.getElementById('riskBadge');
const riskDesc     = document.getElementById('riskDesc');
const flagsList    = document.getElementById('flagsList');
const flagCount    = document.getElementById('flagCount');
const scoreDisplay = document.getElementById('scoreDisplay');
const scoreBar     = document.getElementById('scoreBar');

const CIRCUMFERENCE = 251.2;

const FLAG_ICONS = [
  ["urgency",        "⏰"],
  ["financial",      "💸"],
  ["phishing",       "🎣"],
  ["credential",     "🎣"],
  ["prize",          "🎁"],
  ["lottery",        "🎁"],
  ["impersonation",  "🎭"],
  ["authority",      "🎭"],
  ["capital",        "🔤"],
  ["uppercase",      "📢"],
  ["exclamation",    "❗"],
  ["password",       "🔑"],
  ["pin",            "🔑"],
  ["social security","🪪"],
  ["bank",           "🏦"],
  ["routing",        "🏦"],
  ["credit card",    "💳"],
  ["cvv",            "💳"],
  ["ip address",     "🌐"],
  ["shortened",      "🔗"],
  ["obfuscated",     "🔗"],
  ["click-here",     "👆"],
  ["click here",     "👆"],
  ["dismiss",        "🚫"],
  ["monetary",       "💰"],
  ["no fraud",       "✅"],
];

emailInput.addEventListener('input', () => {
  document.getElementById('charCount').textContent =
    emailInput.value.length.toLocaleString() + ' characters';
});

async function analyzeEmail() {
  const text = emailInput.value.trim();
  if (!text) {
    emailInput.style.borderColor = '#ef4444';
    emailInput.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.18)';
    setTimeout(() => {
      emailInput.style.borderColor = '';
      emailInput.style.boxShadow = '';
    }, 700);
    return;
  }

  analyzeBtn.classList.add('loading');
  analyzeBtn.innerHTML = '<span class="btn-icon">&#9650;</span> Analyzing…';

  try {
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: text }),
    });
    if (!res.ok) throw new Error('Server error');
    const data = await res.json();
    displayResult(data);
  } catch {
    alert('Analysis failed. Make sure the Flask server is running.');
  } finally {
    analyzeBtn.classList.remove('loading');
    analyzeBtn.innerHTML = '<span class="btn-icon">&#9650;</span> Analyze Email';
  }
}

function displayResult(data) {
  const { score, risk_level, reasons } = data;

  const arcColor = risk_level === 'Safe'      ? '#10b981'
                 : risk_level === 'Suspicious' ? '#f59e0b'
                 :                              '#ef4444';

  gaugeArc.style.transition = 'none';
  gaugeArc.setAttribute('stroke-dashoffset', CIRCUMFERENCE);
  gaugeArc.setAttribute('stroke', arcColor);

  requestAnimationFrame(() => requestAnimationFrame(() => {
    gaugeArc.style.transition =
      'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1), stroke 0.4s ease';
    gaugeArc.setAttribute('stroke-dashoffset', CIRCUMFERENCE * (1 - score / 100));
  }));

  animateCounter(gaugeScore,   0, score, 1200);
  animateCounter(scoreDisplay, 0, score, 1200);

  scoreBar.style.backgroundColor = arcColor;
  scoreBar.style.width = '0%';
  requestAnimationFrame(() => requestAnimationFrame(() => {
    scoreBar.style.width = score + '%';
  }));

  const slugMap = { 'Safe': 'safe', 'Suspicious': 'suspicious', 'High Risk': 'high-risk' };
  riskBadge.textContent = risk_level;
  riskBadge.className = 'risk-badge ' + (slugMap[risk_level] || 'safe');

  const descs = {
    'Safe':      'No significant fraud indicators found. This email appears legitimate.',
    'Suspicious':'Some patterns suggest possible deception. Exercise caution.',
    'High Risk': 'Multiple strong fraud indicators detected. Do not engage.',
  };
  riskDesc.textContent = descs[risk_level] || '';

  flagCount.textContent = reasons.length;

  flagsList.innerHTML = '';
  reasons.forEach((reason, idx) => {
    const li = document.createElement('li');
    li.className = 'flag-item ' + flagSeverity(reason);
    li.style.animationDelay = `${idx * 0.07}s`;
    const icon = pickIcon(reason);
    li.innerHTML = `<span class="flag-icon">${icon}</span><span>${reason}</span>`;
    flagsList.appendChild(li);
  });

  resultCard.classList.remove('hidden');
  resultCard.style.display = 'block';
  requestAnimationFrame(() => requestAnimationFrame(() => {
    resultCard.classList.add('visible');
  }));

  setTimeout(() => {
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 120);
}

function flagSeverity(reason) {
  const r = reason.toLowerCase();
  if (r.includes('no fraud')) return 'flag-safe';
  if (r.includes('password') || r.includes('pin') || r.includes('ssn') ||
      r.includes('social security') || r.includes('bank') || r.includes('routing') ||
      r.includes('credit card') || r.includes('cvv') || r.includes('ip address')) {
    return 'flag-critical';
  }
  if (r.includes('urgency') || r.includes('exclamation') || r.includes('capital') ||
      r.includes('uppercase') || r.includes('monetary') || r.includes('financial') ||
      r.includes('dismiss')) {
    return 'flag-warning';
  }
  return 'flag-phish';
}

function pickIcon(reason) {
  const lower = reason.toLowerCase();
  for (const [keyword, icon] of FLAG_ICONS) {
    if (lower.includes(keyword)) return icon;
  }
  return '⚠️';
}

function animateCounter(el, from, to, duration) {
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function clearAll() {
  resultCard.classList.remove('visible');
  setTimeout(() => {
    resultCard.classList.add('hidden');
    resultCard.style.display = '';
    flagsList.innerHTML = '';
    gaugeScore.textContent = '0';
    gaugeArc.setAttribute('stroke-dashoffset', CIRCUMFERENCE);
    riskBadge.className = 'risk-badge';
    riskBadge.textContent = '--';
    riskDesc.textContent = 'Analysis pending';
    flagCount.textContent = '0';
    scoreDisplay.textContent = '0';
    scoreBar.style.width = '0%';
  }, 500);

  emailInput.value = '';
  document.getElementById('charCount').textContent = '0 characters';
  emailInput.focus();
  document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
