async function postJson(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

async function getJson(url) {
  const res = await fetch(url, { method: "GET" });
  return res.json();
}

function $(id) {
  return document.getElementById(id);
}

function setHidden(id, hidden) {
  $(id).classList.toggle("hidden", !!hidden);
}

function renderPatternList(listEl, items) {
  listEl.innerHTML = "";
  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No notable patterns detected.";
    listEl.appendChild(li);
    return;
  }
  for (const it of items) {
    const li = document.createElement("li");
    const sev = it.severity ? it.severity.toUpperCase() : "INFO";
    li.textContent = `${it.name} (${sev}) — ${it.evidence || ""}`.trim();
    listEl.appendChild(li);
  }
}

function updateDashboard() {
  getJson("/history")
    .then((data) => {
      // Optional if elements exist
      if ($("totalAnalyses")) $("totalAnalyses").textContent = data.total_analyses ?? 0;
      if ($("avgStrength")) $("avgStrength").textContent = data.average_strength_score ?? 0;
      if ($("strongPct")) $("strongPct").textContent = `${(data.strong_password_percentage ?? 0).toFixed(1)}%`;
      if ($("weakPct")) $("weakPct").textContent = `${(data.weak_password_percentage ?? 0).toFixed(1)}%`;
    })
    .catch(() => {
      // ignore; dashboard is best-effort
    });
}

function updateStrengthUI(result) {
  const score = result.strength_score ?? 0;
  const bucket = result.bucket ?? "—";
  const label = result.progress_label ?? bucket;

  $("strengthLabel").textContent = bucket;
  $("scoreValue").textContent = score;
  $("riskLevel").textContent = result.risk_level ?? "—";

  $("entropyValue").textContent = (result.entropy_bits ?? 0).toFixed(2);
  $("entropyLabel").textContent = result.entropy_label ?? "—";

  const pct = Math.max(0, Math.min(100, score));
  $("progressBar").style.width = `${pct}%`;

  // Show feedback box
  const fb = result.input_feedback || {};
  setHidden("feedbackBox", !fb.message);

  $("feedbackTitle").textContent = fb.type === "warning" ? "Warning" : "Info";
  $("feedbackText").textContent = fb.message || "";

  const d = result.detailed || {};
  $("lengthScore").textContent = d.length_score ?? "—";
  $("complexityScore").textContent = d.complexity_score ?? "—";
  $("entropyScore").textContent = d.entropy_score ?? "—";
  $("overallScore").textContent = result.overall_security_score ?? "—";

  renderPatternList($("patternList"), d.pattern_detection || []);
  renderPatternList($("securityList"), d.security_checks || []);

  // Attack estimate quick render (if elements exist)
  if ($("bruteForce")) $("bruteForce").textContent = result.attack_estimates?.brute_force ?? "—";
  if ($("dictionary")) $("dictionary").textContent = result.attack_estimates?.dictionary ?? "—";
  if ($("credentialStuffing")) $("credentialStuffing").textContent = result.attack_estimates?.credential_stuffing ?? "—";

  // Recommendations
  const recEl = $("recommendationsList");
  if (recEl) {
    recEl.innerHTML = "";
    const rec = result.recommendations || [];
    for (const r of rec) {
      const li = document.createElement("li");
      li.textContent = r;
      recEl.appendChild(li);
    }
  }
}

function validate(password) {
  if (password === null || password === undefined) return { ok: false, msg: "Password cannot be empty." };
  if (password.length === 0) return { ok: false, msg: "Password cannot be empty." };
  return { ok: true, msg: "" };
}

async function analyzeCurrent({ showError = true } = {}) {
  const password = $("passwordInput").value || "";
  const v = validate(password);
  if (!v.ok) {
    if (showError) {
      $("errorBanner").textContent = v.msg;
      setHidden("errorBanner", false);
    }
    // Reset UI
    updateStrengthUI({
      strength_score: 0,
      bucket: "Very Weak",
      progress_label: "Very Weak",
      entropy_bits: 0,
      entropy_label: "Low Entropy",
      overall_security_score: 0,
      risk_level: "High",
      detailed: { length_score: 0, complexity_score: 0, entropy_score: 0, pattern_detection: [], security_checks: [] },
      input_feedback: { type: "error", message: v.msg },
      recommendations: ["Enter a password to analyze."],
      attack_estimates: { brute_force: "Instantly", dictionary: "Instantly", credential_stuffing: "Instantly" },
    });
    return;
  }

  if (showError) setHidden("errorBanner", true);

  const result = await postJson("/analyze", { password });
  updateStrengthUI(result);
}

document.addEventListener("DOMContentLoaded", () => {
  // Buttons
  $("analyzeBtn").addEventListener("click", () => analyzeCurrent());
  $("clearBtn").addEventListener("click", () => {
    $("passwordInput").value = "";
    setHidden("errorBanner", true);
    updateStrengthUI({
      strength_score: 0,
      bucket: "Very Weak",
      progress_label: "Very Weak",
      entropy_bits: 0,
      entropy_label: "Low Entropy",
      overall_security_score: 0,
      risk_level: "High",
      detailed: { length_score: 0, complexity_score: 0, entropy_score: 0, pattern_detection: [], security_checks: [] },
      input_feedback: { type: "error", message: "Password cannot be empty." },
      recommendations: ["Enter a password to analyze."],
      attack_estimates: { brute_force: "Instantly", dictionary: "Instantly", credential_stuffing: "Instantly" },
    });
  });

  // Toggle show/hide
  $("toggleBtn").addEventListener("click", () => {
    const inp = $("passwordInput");
    const isMasked = inp.type === "password";
    inp.type = isMasked ? "text" : "password";
    $("toggleBtn").textContent = isMasked ? "Hide" : "Show";
  });

  // Real-time analysis on type (debounced)
  let t = null;
  $("passwordInput").addEventListener("input", () => {
    if (t) clearTimeout(t);
    t = setTimeout(() => analyzeCurrent({ showError: false }), 180);
  });

  // Dashboard best-effort
  updateDashboard();

  // Initial UI state
  updateStrengthUI({
    strength_score: 0,
    bucket: "Very Weak",
    progress_label: "Very Weak",
    entropy_bits: 0,
    entropy_label: "Low Entropy",
    overall_security_score: 0,
    risk_level: "High",
    detailed: { length_score: 0, complexity_score: 0, entropy_score: 0, pattern_detection: [], security_checks: [] },
    input_feedback: { type: "error", message: "Enter a password to analyze." },
    recommendations: ["Enter a password to analyze."],
    attack_estimates: { brute_force: "Instantly", dictionary: "Instantly", credential_stuffing: "Instantly" },
  });
});
