// ── Detection engine (ported from detector.py) ──────────────────────────────

const KEYWORD_CATEGORIES = [
  {
    label: "Urgency words detected",
    keywords: ["act now","urgent","immediate action","respond immediately",
               "limited time","expires today","account suspended","verify immediately",
               "last chance","final notice","within 24 hours","within 48 hours",
               "time sensitive","action required","don't delay"],
    weight: 4, cap: 20
  },
  {
    label: "Financial fraud phrases detected",
    keywords: ["wire transfer","western union","money order","bank transfer",
               "send money","transfer funds","nigerian prince","inheritance funds",
               "unclaimed funds","lottery winnings","prize money","financial assistance",
               "investment opportunity","guaranteed return","risk free"],
    weight: 6, cap: 30
  },
  {
    label: "Phishing / credential harvesting phrases detected",
    keywords: ["click here to verify","confirm your account","update your information",
               "your account will be closed","verify your identity","login to your account",
               "sign in to confirm","reset your password","enter your credentials",
               "your password has expired","account verification required",
               "provide your details","validate your account"],
    weight: 7, cap: 35
  },
  {
    label: "Fake prize / lottery phrases detected",
    keywords: ["you have won","congratulations you","selected as winner",
               "claim your prize","you are the lucky","lucky winner",
               "claim your reward","free gift","you have been chosen",
               "winning notification","award notification","jackpot"],
    weight: 5, cap: 25
  },
  {
    label: "Impersonation of trusted authority detected",
    keywords: ["irs notice","internal revenue service","social security administration",
               "microsoft support","apple support","paypal security",
               "amazon security","google account team","federal bureau",
               "department of homeland","official notice from"],
    weight: 5, cap: 20
  }
];

const REGEX_RULES = [
  { re: /(?:[A-Z]{5,}\s*){3,}/,                                    delta: 15, reason: "Excessive use of capital letters (shouting pattern)" },
  { re: /!{2,}|(?:[^!]*!){4,}/,                                    delta: 10, reason: "Excessive exclamation marks (pressure tactic)" },
  { re: /\b(?:password|passwd|pin)\b/i,                            delta: 20, reason: "Directly asks for password or PIN" },
  { re: /\b(?:ssn|social security number|social security no)\b/i,  delta: 20, reason: "Requests Social Security Number" },
  { re: /\b(?:bank account|account number|routing number)\b/i,     delta: 15, reason: "Requests banking details" },
  { re: /\b(?:credit card|card number|cvv|expiry date)\b/i,        delta: 15, reason: "Requests credit card information" },
  { re: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,        delta: 18, reason: "Link uses raw IP address instead of domain (suspicious)" },
  { re: /bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.gy/i,   delta: 12, reason: "Contains shortened/obfuscated URL" },
  { re: /\bclick\s+(?:here|below|this\s+link)\b/i,                 delta: 8,  reason: "Generic click-here link anchor (phishing pattern)" },
  { re: /\bdo\s+not\s+(?:ignore|delete|discard)\b/i,               delta: 6,  reason: "Instruction not to dismiss email (pressure tactic)" },
  { re: /\$\s*\d[\d,]*(?:\.\d{2})?.*\$\s*\d[\d,]*(?:\.\d{2})?.*\$\s*\d[\d,]*/i, delta: 10, reason: "Multiple monetary amounts mentioned (financial lure)" },
];

function analyze(emailText) {
  const lower = emailText.toLowerCase();
  let score = 0;
  const reasons = [];

  for (const { label, keywords, weight, cap } of KEYWORD_CATEGORIES) {
    const hits = keywords.filter(kw => lower.includes(kw));
    if (hits.length) {
      score += Math.min(hits.length * weight, cap);
      reasons.push(`${label} — e.g. "${hits[0]}"`);
    }
  }

  for (const { re, delta, reason } of REGEX_RULES) {
    if (re.test(emailText)) {
      score += delta;
      reasons.push(reason);
    }
  }

  const alpha = [...emailText].filter(c => /[a-zA-Z]/.test(c));
  if (alpha.length > 50) {
    const upperRatio = alpha.filter(c => c >= 'A' && c <= 'Z').length / alpha.length;
    if (upperRatio > 0.4) {
      score += 10;
      reasons.push("Abnormally high uppercase-to-lowercase ratio");
    }
  }

  score = Math.min(score, 100);
  const risk_level = score <= 30 ? "Safe" : score <= 60 ? "Suspicious" : "High Risk";
  if (!reasons.length) reasons.push("No fraud indicators detected");

  return { score, risk_level, reasons };
}

// ── UI ───────────────────────────────────────────────────────────────────────

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
  ["urgency","⏰"],["financial","💸"],["phishing","🎣"],["credential","🎣"],
  ["prize","🎁"],["lottery","🎁"],["impersonation","🎭"],["authority","🎭"],
  ["capital","🔤"],["uppercase","📢"],["exclamation","❗"],["password","🔑"],
  ["pin","🔑"],["social security","🪪"],["bank","🏦"],["routing","🏦"],
  ["credit card","💳"],["cvv","💳"],["ip address","🌐"],["shortened","🔗"],
  ["obfuscated","🔗"],["click-here","👆"],["click here","👆"],
  ["dismiss","🚫"],["monetary","💰"],["no fraud","✅"],
];

emailInput.addEventListener('input', () => {
  document.getElementById('charCount').textContent =
    emailInput.value.length.toLocaleString() + ' characters';
});

function analyzeEmail() {
  const text = emailInput.value.trim();
  if (!text) {
    emailInput.style.borderColor = '#ef4444';
    emailInput.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.18)';
    setTimeout(() => { emailInput.style.borderColor = ''; emailInput.style.boxShadow = ''; }, 700);
    return;
  }
  analyzeBtn.disabled = true;
  analyzeBtn.innerHTML = '<span class="btn-icon">&#9650;</span> Analyzing…';
  setTimeout(() => {
    displayResult(analyze(text));
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = '<span class="btn-icon">&#9650;</span> Analyze Email';
  }, 120);
}

function displayResult(data) {
  const { score, risk_level, reasons } = data;

  const arcColor = risk_level === 'Safe' ? '#10b981' : risk_level === 'Suspicious' ? '#f59e0b' : '#ef4444';

  gaugeArc.style.transition = 'none';
  gaugeArc.setAttribute('stroke-dashoffset', CIRCUMFERENCE);
  gaugeArc.setAttribute('stroke', arcColor);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    gaugeArc.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1), stroke 0.4s ease';
    gaugeArc.setAttribute('stroke-dashoffset', CIRCUMFERENCE * (1 - score / 100));
  }));

  animateCounter(gaugeScore,   0, score, 1200);
  animateCounter(scoreDisplay, 0, score, 1200);

  scoreBar.style.backgroundColor = arcColor;
  scoreBar.style.width = '0%';
  requestAnimationFrame(() => requestAnimationFrame(() => { scoreBar.style.width = score + '%'; }));

  const slugMap = { 'Safe': 'safe', 'Suspicious': 'suspicious', 'High Risk': 'high-risk' };
  riskBadge.textContent = risk_level;
  riskBadge.className = 'risk-badge ' + (slugMap[risk_level] || 'safe');

  riskDesc.textContent = {
    'Safe':      'No significant fraud indicators found. This email appears legitimate.',
    'Suspicious':'Some patterns suggest possible deception. Exercise caution.',
    'High Risk': 'Multiple strong fraud indicators detected. Do not engage.',
  }[risk_level] || '';

  flagCount.textContent = reasons.length;
  flagsList.innerHTML = '';
  reasons.forEach((reason, idx) => {
    const li = document.createElement('li');
    li.className = 'flag-item ' + flagSeverity(reason);
    li.style.animationDelay = `${idx * 0.07}s`;
    li.innerHTML = `<span class="flag-icon">${pickIcon(reason)}</span><span>${reason}</span>`;
    flagsList.appendChild(li);
  });

  resultCard.classList.remove('hidden');
  resultCard.style.display = 'block';
  requestAnimationFrame(() => requestAnimationFrame(() => { resultCard.classList.add('visible'); }));
  setTimeout(() => resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120);
}

function flagSeverity(reason) {
  const r = reason.toLowerCase();
  if (r.includes('no fraud')) return 'flag-safe';
  if (r.includes('password') || r.includes('pin') || r.includes('ssn') ||
      r.includes('social security') || r.includes('bank') || r.includes('routing') ||
      r.includes('credit card') || r.includes('cvv') || r.includes('ip address'))
    return 'flag-critical';
  if (r.includes('urgency') || r.includes('exclamation') || r.includes('capital') ||
      r.includes('uppercase') || r.includes('monetary') || r.includes('financial') ||
      r.includes('dismiss'))
    return 'flag-warning';
  return 'flag-phish';
}

function pickIcon(reason) {
  const lower = reason.toLowerCase();
  for (const [kw, icon] of FLAG_ICONS) if (lower.includes(kw)) return icon;
  return '⚠️';
}

function animateCounter(el, from, to, duration) {
  const start = performance.now();
  (function step(now) {
    const t = Math.min((now - start) / duration, 1);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - t, 3)));
    if (t < 1) requestAnimationFrame(step);
  })(start);
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
