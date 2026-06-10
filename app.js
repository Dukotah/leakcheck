/* LeakCheck — client-side secret detection engine.
 *
 * HARD SECURITY GUARANTEE: This file makes ZERO network calls with user data.
 * There is no fetch / XMLHttpRequest / WebSocket / sendBeacon / Image-ping
 * anywhere in this file. The textarea contents never leave the browser tab.
 * Everything below runs locally on the pasted text.
 *
 * Full secret values are NEVER rendered, copied, or placed in any title/attr.
 * Every preview is masked to first 4 + last 4 chars before it touches the DOM
 * or the clipboard. All user-derived text is inserted via textContent (never
 * raw innerHTML) so pasted code cannot inject markup or run script.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ *
   * Severity ordering / metadata
   * ------------------------------------------------------------------ */
  var SEVERITIES = ["critical", "high", "medium", "low"];
  var SEV_LABEL = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low"
  };
  // Maps a full severity to the abbreviated class suffix the stylesheet uses
  // (.sev-count.crit / .high / .med / .low). Keeps app.js + styles.css in sync.
  var SEV_ABBR = {
    critical: "crit",
    high: "high",
    medium: "med",
    low: "low"
  };

  /* ------------------------------------------------------------------ *
   * Masking — the core safety primitive.
   * Show only first 4 + last 4 chars; collapse the middle to bullets.
   * Short values are mostly/entirely hidden. Whitespace/newlines stripped
   * from the preview so multi-line PEM blocks render as one safe token.
   * ------------------------------------------------------------------ */
  function maskSecret(raw) {
    var s = String(raw).replace(/\s+/g, "");
    if (s.length <= 8) {
      // Too short to safely show both ends — reveal at most first 2 chars.
      var head = s.slice(0, Math.min(2, s.length));
      return head + repeat("•", Math.max(4, s.length - head.length));
    }
    var first = s.slice(0, 4);
    var last = s.slice(-4);
    var midLen = s.length - 8;
    var bullets = repeat("•", Math.min(midLen, 18));
    return first + bullets + last;
  }

  function repeat(ch, n) {
    var out = "";
    for (var i = 0; i < n; i++) out += ch;
    return out;
  }

  /* ------------------------------------------------------------------ *
   * Shannon entropy (bits per char) — used to filter generic/entropy hits
   * so we only flag values that actually look random (real secrets), not
   * ordinary words assigned to a variable.
   * ------------------------------------------------------------------ */
  function shannonEntropy(str) {
    if (!str.length) return 0;
    var freq = Object.create(null);
    for (var i = 0; i < str.length; i++) {
      var c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }
    var entropy = 0;
    var len = str.length;
    for (var k in freq) {
      var p = freq[k] / len;
      entropy -= p * (Math.log(p) / Math.LN2);
    }
    return entropy;
  }

  /* ------------------------------------------------------------------ *
   * Named, high-confidence detectors.
   * Each: { name, severity, why, regex, group? }
   * `regex` MUST be global ('g'). If `group` is set, that capture group is
   * the secret to mask; otherwise the whole match is the secret.
   * `why` is a one-sentence danger explanation. `rotate` names where to
   * rotate, used to build remediation text.
   * ------------------------------------------------------------------ */
  var DETECTORS = [
    {
      name: "AWS Access Key ID",
      severity: "high",
      regex: /\bAKIA[0-9A-Z]{16}\b/g,
      why: "An AWS access key ID identifies an IAM principal and, paired with its secret, grants programmatic access to your AWS account.",
      rotate: "the AWS IAM console (deactivate then delete the key pair)"
    },
    {
      name: "AWS Secret Access Key",
      severity: "critical",
      // Secret assigned to an aws-ish key, or a bare 40-char base64 secret.
      regex: /(?:aws.{0,20})?(?:secret|SECRET)[^\n]{0,20}?["'=:\s]+([A-Za-z0-9\/+]{40})\b/g,
      group: 1,
      why: "The AWS secret access key is the password half of an AWS credential pair and lets an attacker fully control your AWS resources and bill.",
      rotate: "the AWS IAM console (rotate the access key pair immediately)"
    },
    {
      name: "GitHub Personal Access Token",
      severity: "critical",
      regex: /\bghp_[0-9A-Za-z]{36}\b/g,
      why: "A GitHub PAT can read and push to your repositories and act on your behalf across GitHub.",
      rotate: "GitHub → Settings → Developer settings → Personal access tokens (revoke it)"
    },
    {
      name: "GitHub Fine-grained PAT",
      severity: "critical",
      regex: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/g,
      why: "A fine-grained GitHub PAT grants scoped repo/org access and can be replayed by anyone who finds it.",
      rotate: "GitHub → Settings → Developer settings → Fine-grained tokens (revoke it)"
    },
    {
      name: "GitHub OAuth / App Token",
      severity: "critical",
      regex: /\b(?:gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g,
      why: "GitHub OAuth, user-to-server, server-to-server, and refresh tokens authenticate GitHub API calls and can hijack a session or app installation.",
      rotate: "GitHub (revoke the OAuth app authorization / regenerate the app token)"
    },
    {
      name: "GitLab Personal Access Token",
      severity: "critical",
      regex: /\bglpat-[0-9A-Za-z_\-]{20,}\b/g,
      why: "A GitLab PAT can clone, push, and administer your GitLab projects depending on its scopes.",
      rotate: "GitLab → Preferences → Access Tokens (revoke it)"
    },
    {
      name: "OpenAI API Key (project)",
      severity: "critical",
      regex: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b/g,
      why: "An OpenAI project key bills your account for API usage and can be abused to run up large charges.",
      rotate: "the OpenAI dashboard → API keys (revoke it)"
    },
    {
      name: "OpenAI API Key",
      severity: "critical",
      // Avoid colliding with sk-proj / sk-ant by requiring a non-'proj'/'ant' lead.
      regex: /\bsk-(?!proj-|ant-)[A-Za-z0-9]{20,}\b/g,
      why: "An OpenAI API key bills your account for model usage and can be drained by anyone who obtains it.",
      rotate: "the OpenAI dashboard → API keys (revoke it)"
    },
    {
      name: "Anthropic API Key",
      severity: "critical",
      regex: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
      why: "An Anthropic API key bills your account for Claude usage and can be abused for unauthorized requests.",
      rotate: "the Anthropic console → API keys (revoke it)"
    },
    {
      name: "Stripe Secret Key (live)",
      severity: "critical",
      regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g,
      why: "A live Stripe secret key can create charges, issue refunds, and read customer/payment data on your real account.",
      rotate: "the Stripe dashboard → Developers → API keys (roll the key immediately)"
    },
    {
      name: "Stripe Secret Key (test)",
      severity: "high",
      regex: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}\b/g,
      why: "A Stripe test secret key exposes your test environment and signals a secret-in-code habit that often repeats with live keys.",
      rotate: "the Stripe dashboard → Developers → API keys (roll the test key)"
    },
    {
      name: "Stripe Publishable Live Key",
      severity: "low",
      regex: /\bpk_live_[0-9A-Za-z]{20,}\b/g,
      why: "A Stripe publishable key is meant to be public, but its presence often means secret keys are nearby in the same file.",
      rotate: "the Stripe dashboard (publishable keys are public, but review the file for secret keys)"
    },
    {
      name: "Google API Key",
      severity: "high",
      // {35,} (not exactly 35) so over-length / adjacent-char paste variants are
      // still flagged; canonical 39-char keys remain caught.
      regex: /AIza[0-9A-Za-z_\-]{35,}/g,
      why: "A Google API key can call billable Google/Firebase/Maps APIs on your project and rack up charges if unrestricted.",
      rotate: "Google Cloud Console → APIs & Services → Credentials (regenerate and add restrictions)"
    },
    {
      name: "Slack Token",
      severity: "critical",
      regex: /\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/g,
      why: "A Slack token can read and post messages and access files across your workspace depending on its scopes.",
      rotate: "the Slack app config / workspace admin (revoke the token)"
    },
    {
      name: "Twilio API Key SID",
      severity: "high",
      regex: /\bSK[0-9a-f]{32}\b/g,
      why: "A Twilio API key SID, paired with its secret, can send SMS/voice and incur charges on your Twilio account.",
      rotate: "the Twilio console → API keys (delete the key)"
    },
    {
      name: "SendGrid API Key",
      severity: "critical",
      regex: /\bSG\.[\w\-]{22}\.[\w\-]{43}\b/g,
      why: "A SendGrid API key can send email as your domain, enabling spam or phishing from your reputation.",
      rotate: "the SendGrid dashboard → API Keys (delete the key)"
    },
    {
      name: "Mailgun API Key",
      severity: "high",
      regex: /\bkey-[0-9a-f]{32}\b/g,
      why: "A Mailgun API key can send email through your account and read sending logs.",
      rotate: "the Mailgun dashboard → API security (regenerate the key)"
    },
    {
      name: "npm Access Token",
      severity: "critical",
      regex: /\bnpm_[0-9A-Za-z]{36}\b/g,
      why: "An npm token can publish packages under your account, a vector for supply-chain attacks.",
      rotate: "npmjs.com → Access Tokens (revoke it)"
    },
    {
      name: "Shopify Access Token",
      severity: "critical",
      regex: /\b(?:shpat|shpss|shpca|shppa)_[0-9a-fA-F]{32}\b/g,
      why: "A Shopify access token can read/modify store data including orders and customers.",
      rotate: "the Shopify admin / partner dashboard (revoke the app token)"
    },
    {
      name: "Discord Bot Token",
      severity: "high",
      regex: /\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b/g,
      why: "A Discord bot token gives full control of the bot account, including reading and sending messages in every server it joined.",
      rotate: "the Discord developer portal → Bot (reset the token)"
    },
    {
      name: "JSON Web Token (JWT)",
      severity: "medium",
      regex: /\beyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+\b/g,
      why: "A JWT can carry session identity or claims and may grant access until it expires if it is a live token.",
      rotate: "your auth provider / app (invalidate the session and rotate signing keys if it is a server secret)"
    },
    {
      name: "Private Key (PEM)",
      severity: "critical",
      regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
      why: "A PEM private key is the cryptographic identity behind TLS, SSH, or signing — whoever holds it can impersonate your service.",
      rotate: "the system that issued it (generate a new key pair and revoke/replace the old one everywhere)"
    },
    {
      name: "Database URI with credentials",
      severity: "critical",
      regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^\s:@\/]+:[^\s:@\/]+@[^\s\/"']+/g,
      why: "A database connection string with an inline username and password grants direct read/write access to your data.",
      rotate: "your database (rotate the database user's password and restrict network access)"
    },
    {
      name: "Authorization / Bearer header",
      severity: "high",
      regex: /(?:Authorization|authorization)\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9_\-\.=+\/]{12,})/g,
      group: 1,
      why: "A hard-coded Authorization header embeds a live credential that authenticates requests to a protected API.",
      rotate: "the issuing service (revoke the token and inject it from an env var at runtime)"
    },
    {
      name: "Generic API key / secret assignment",
      severity: "medium",
      // KEY = "value" where KEY looks secret-ish and value is long-ish.
      regex: /(?:^|[^\w])([A-Za-z][A-Za-z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|AUTH))\s*[:=]\s*["'`]([^"'`\n]{8,})["'`]/gi,
      group: 2,
      why: "A secret-looking variable is assigned a value directly in source, so anyone with the code has the credential.",
      rotate: "the owning service (rotate the value and load it from an environment variable instead)",
      entropyMin: 2.6 // gate generic hits so 'password = changeme' style noise is filtered
    }
  ];

  /* Entropy fallback: long high-entropy value assigned to a secret-looking key
   * that the named/generic detectors did not already catch. */
  var ENTROPY_RE = /(?:^|[^\w])([A-Za-z][A-Za-z0-9_]*(?:key|secret|token|password|passwd|auth|credential|api)[A-Za-z0-9_]*)\s*[:=]\s*["'`]?([A-Za-z0-9_\-\.+\/=]{24,})["'`]?/gi;
  var ENTROPY_THRESHOLD = 4.0; // bits/char — random base64-ish strings sit ~4.5+

  /* ------------------------------------------------------------------ *
   * Line-number helper: maps a character offset to a 1-based line number.
   * Precompute line-start offsets once per scan for O(log n) lookups.
   * ------------------------------------------------------------------ */
  function buildLineIndex(text) {
    var starts = [0];
    for (var i = 0; i < text.length; i++) {
      if (text[i] === "\n") starts.push(i + 1);
    }
    return starts;
  }
  function lineAt(starts, offset) {
    var lo = 0, hi = starts.length - 1, ans = 0;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (starts[mid] <= offset) { ans = mid; lo = mid + 1; }
      else hi = mid - 1;
    }
    return ans + 1;
  }

  /* ------------------------------------------------------------------ *
   * Core scan: run every detector + entropy fallback over the text.
   * Returns an array of finding objects (secret value kept only long enough
   * to compute a mask; never stored on the returned object).
   * ------------------------------------------------------------------ */
  function scan(text) {
    var findings = [];
    var lineIndex = buildLineIndex(text);
    var seen = Object.create(null); // dedupe by name + masked + line

    function push(name, severity, why, rotate, secretRaw, offset) {
      if (!secretRaw) return;
      var line = lineAt(lineIndex, offset);
      var masked = maskSecret(secretRaw);
      var key = name + "|" + masked + "|" + line;
      if (seen[key]) return;
      seen[key] = true;
      findings.push({
        name: name,
        severity: severity,
        why: why,
        rotate: rotate,
        masked: masked,
        line: line
      });
    }

    // Named + generic detectors.
    for (var d = 0; d < DETECTORS.length; d++) {
      var det = DETECTORS[d];
      var re = det.regex;
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(text)) !== null) {
        if (m.index === re.lastIndex) re.lastIndex++; // guard zero-width
        var secret = det.group != null ? m[det.group] : m[0];
        if (!secret) continue;
        // Offset of the secret within the full match (so line number points
        // at the secret, not at the start of a long PEM/match).
        var secretOffset = m.index;
        if (det.group != null) {
          var gi = m[0].indexOf(secret);
          if (gi >= 0) secretOffset = m.index + gi;
        }
        if (det.entropyMin != null) {
          var clean = secret.replace(/\s+/g, "");
          if (shannonEntropy(clean) < det.entropyMin) continue;
        }
        push(det.name, det.severity, det.why, det.rotate, secret, secretOffset);
      }
    }

    // Entropy fallback — only fire when the value looks genuinely random and
    // isn't already covered by a named/generic finding on the same line.
    ENTROPY_RE.lastIndex = 0;
    var em;
    while ((em = ENTROPY_RE.exec(text)) !== null) {
      if (em.index === ENTROPY_RE.lastIndex) ENTROPY_RE.lastIndex++;
      var val = em[2];
      if (!val) continue;
      var ent = shannonEntropy(val);
      if (ent < ENTROPY_THRESHOLD) continue;
      var gidx = em[0].indexOf(val);
      var off = em.index + (gidx >= 0 ? gidx : 0);
      var ln = lineAt(lineIndex, off);
      // Skip if a stronger detector already flagged this exact line.
      var already = false;
      for (var f = 0; f < findings.length; f++) {
        if (findings[f].line === ln) { already = true; break; }
      }
      if (already) continue;
      push(
        "High-entropy secret (heuristic)",
        "medium",
        "This value is long and highly random, the signature of an API key or token even though it matches no known provider format.",
        "the owning service (rotate it and move it to an environment variable or secret manager)",
        val,
        off
      );
    }

    // Sort: severity (critical first), then line number.
    findings.sort(function (a, b) {
      var sa = SEVERITIES.indexOf(a.severity);
      var sb = SEVERITIES.indexOf(b.severity);
      if (sa !== sb) return sa - sb;
      return a.line - b.line;
    });

    return findings;
  }

  /* ------------------------------------------------------------------ *
   * Remediation text — shared concrete guidance appended to each finding.
   * ------------------------------------------------------------------ */
  function remediationText(finding) {
    return (
      "Rotate this secret in " + finding.rotate + ". " +
      "Then stop committing it: remove the literal from source, load it from an environment variable or a secret manager (e.g. 1Password, Doppler, AWS Secrets Manager, Vault), " +
      "and add the file (.env, config) to your .gitignore. " +
      "Finally, scrub it from git history with git filter-repo or BFG Repo-Cleaner and force-push, since the value is compromised once it has been pushed anywhere."
    );
  }

  /* ------------------------------------------------------------------ *
   * DOM rendering. All user-derived text uses textContent. The only
   * innerHTML we set is wiping the results container (no user data).
   * ------------------------------------------------------------------ */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text; // safe: escaped by the DOM
    return node;
  }

  /* ------------------------------------------------------------------ *
   * Contextual lead capture. When secrets are found, offer a no-obligation
   * "get these fixed" quote that pre-fills an email to Copper Bay Tech with
   * the finding COUNTS and secret TYPES only. The raw secret values are never
   * stored on findings and are deliberately never placed in the email body.
   * ------------------------------------------------------------------ */
  function buildFixCta(findings, counts, total) {
    // Distinct secret types (the .name field), order-preserving, capped.
    var seenType = Object.create(null);
    var types = [];
    for (var i = 0; i < findings.length; i++) {
      var nm = findings[i].name;
      if (nm && !seenType[nm]) { seenType[nm] = true; types.push(nm); }
    }
    var sevParts = [];
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (counts[sev]) sevParts.push(counts[sev] + " " + SEV_LABEL[sev].toLowerCase());
    }
    var typeList = types.slice(0, 8).map(function (t) { return "- " + t; }).join("\n");
    var subject =
      "Fix quote — LeakCheck flagged " + total +
      (total === 1 ? " potential secret" : " potential secrets") + " in my code";
    var body =
      "Hi Copper Bay,\n\n" +
      "I ran LeakCheck and it flagged " + total +
      (total === 1 ? " potential secret" : " potential secrets") +
      (sevParts.length ? " (" + sevParts.join(", ") + ")" : "") +
      (typeList ? ", including:\n" + typeList : ".") +
      "\n\nI'd like a no-obligation quote to rotate these and scrub them from git history. Thanks!";
    var href =
      "mailto:contact@copperbaytech.com?subject=" + encodeURIComponent(subject) +
      "&body=" + encodeURIComponent(body);

    var cta = el("div", "fix-cta");
    cta.setAttribute(
      "style",
      "display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap;" +
      "margin:18px 0 6px;padding:16px 18px;border:1px solid var(--copper,#bf6b3c);" +
      "background:var(--copper-tint,#f6ebe2);border-radius:12px"
    );
    var copy = el("div");
    copy.setAttribute("style", "max-width:48ch");
    var strong = el("strong", null, "Want these fixed for you?");
    strong.setAttribute("style", "display:block;margin-bottom:3px");
    var sub = el(
      "span",
      null,
      "Copper Bay Tech rotates exposed secrets and scrubs them from git history. " +
      "Get a no-obligation quote — your scan summary is pre-filled in the email (your code is never sent)."
    );
    sub.setAttribute("style", "color:var(--muted,#665f54);font-size:14px");
    copy.appendChild(strong);
    copy.appendChild(sub);

    var btn = el("a", "btn primary", "Get a free fix quote →");
    btn.setAttribute("href", href);
    btn.setAttribute("style", "white-space:nowrap");

    cta.appendChild(copy);
    cta.appendChild(btn);
    return cta;
  }

  function render(findings, results, liveRegion, onCopy) {
    results.textContent = ""; // clear previous render (no user data involved)

    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < findings.length; i++) counts[findings[i].severity]++;

    /* Results header: heading + "Copy report" button (#copy-btn). The button
     * is injected here on every render so it always matches the current scan. */
    var head = el("div", "results-head");
    head.appendChild(el("h2", null, "Scan results"));
    var copyBtn = el("button", "copy-button");
    copyBtn.type = "button";
    copyBtn.id = "copy-btn";
    copyBtn.textContent = "Copy report";
    copyBtn.setAttribute("data-label", "Copy report");
    if (typeof onCopy === "function") {
      copyBtn.addEventListener("click", function (e) {
        e.preventDefault();
        onCopy(copyBtn);
      });
    }
    head.appendChild(copyBtn);
    results.appendChild(head);

    if (findings.length === 0) {
      var empty = el("div", "empty-state");
      empty.appendChild(el("div", "es-icon", "✓"));
      empty.appendChild(el("h3", null, "No secrets detected"));
      empty.appendChild(
        el(
          "p",
          null,
          "No secrets detected — but a clean scan is not a guarantee; entropy detection can miss custom tokens. Always review code by hand and keep credentials out of source control."
        )
      );
      results.appendChild(empty);
      results.hidden = false;
      announce(liveRegion, "Scan complete. No secrets detected.");
      return;
    }

    /* Summary bar with counts by severity. */
    var bar = el("div", "summary-bar");
    var total = findings.length;
    var headline = el(
      "p",
      "summary-headline",
      total + (total === 1 ? " potential secret found" : " potential secrets found")
    );
    bar.appendChild(headline);

    var pills = el("div", "summary-counts");
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (!counts[sev]) continue;
      var pill = el("span", "sev-count " + SEV_ABBR[sev]);
      pill.appendChild(el("span", "dot"));
      pill.appendChild(el("span", "n", String(counts[sev])));
      pill.appendChild(el("span", null, SEV_LABEL[sev]));
      pills.appendChild(pill);
    }
    bar.appendChild(pills);
    results.appendChild(bar);

    /* Findings grouped by severity, critical first. */
    for (var g = 0; g < SEVERITIES.length; g++) {
      var groupSev = SEVERITIES[g];
      var group = findings.filter(function (f) { return f.severity === groupSev; });
      if (!group.length) continue;

      var groupWrap = el("div", "finding-group");
      var groupHead = el(
        "h3",
        "group-head",
        SEV_LABEL[groupSev] + " (" + group.length + ")"
      );
      groupWrap.appendChild(groupHead);

      for (var c = 0; c < group.length; c++) {
        groupWrap.appendChild(buildCard(group[c]));
      }
      results.appendChild(groupWrap);
    }

    results.appendChild(buildFixCta(findings, counts, total));

    results.hidden = false;
    announce(
      liveRegion,
      "Scan complete. " +
        total +
        (total === 1 ? " potential secret found: " : " potential secrets found: ") +
        summaryPhrase(counts) +
        "."
    );
  }

  function summaryPhrase(counts) {
    var parts = [];
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (counts[sev]) parts.push(counts[sev] + " " + SEV_LABEL[sev].toLowerCase());
    }
    return parts.join(", ");
  }

  function buildCard(finding) {
    var card = el("article", "finding sev-" + finding.severity);

    var head = el("div", "finding-head");
    var badge = el("span", "sev-badge sev-" + finding.severity);
    badge.appendChild(el("span", "dot"));
    badge.appendChild(el("span", null, SEV_LABEL[finding.severity]));
    head.appendChild(badge);
    head.appendChild(el("span", "finding-title", finding.name));
    // .line-chip::before already prints "L", so emit only the number to avoid "LLine 5".
    var lineChip = el("span", "line-chip", String(finding.line));
    head.appendChild(lineChip);
    card.appendChild(head);

    /* Masked value — monospace, never the full secret. */
    var valWrap = el("code", "secret-snippet");
    valWrap.setAttribute("aria-label", "Masked secret preview");
    valWrap.appendChild(el("span", "label", "Match: "));
    valWrap.appendChild(el("span", "masked", finding.masked)); // already masked
    card.appendChild(valWrap);

    card.appendChild(el("p", "finding-desc", finding.why));

    var fix = el("div", "fix");
    fix.appendChild(el("span", "fix-label", "How to fix"));
    fix.appendChild(el("p", "fix-body", remediationText(finding)));
    card.appendChild(fix);

    return card;
  }

  function announce(liveRegion, msg) {
    if (!liveRegion) return;
    liveRegion.textContent = msg;
  }

  /* ------------------------------------------------------------------ *
   * Plain-text report for the clipboard. Secrets are MASKED here too.
   * ------------------------------------------------------------------ */
  function buildReport(findings) {
    var lines = [];
    lines.push("LeakCheck report");
    lines.push("Generated locally in the browser — no data was uploaded.");
    lines.push("");

    if (!findings.length) {
      lines.push("No secrets detected.");
      lines.push("(A clean scan is not a guarantee; entropy detection can miss custom tokens.)");
      return lines.join("\n");
    }

    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < findings.length; i++) counts[findings[i].severity]++;

    lines.push(
      findings.length +
        (findings.length === 1 ? " potential secret found." : " potential secrets found.")
    );
    lines.push(
      "Severity: " +
        SEVERITIES.map(function (s) { return counts[s] + " " + s; }).join(", ")
    );
    lines.push("");
    lines.push("----------------------------------------");

    for (var f = 0; f < findings.length; f++) {
      var x = findings[f];
      lines.push("");
      lines.push("[" + SEV_LABEL[x.severity].toUpperCase() + "] " + x.name + "  (line " + x.line + ")");
      lines.push("  Match:  " + x.masked + "   (masked — full value never shown)");
      lines.push("  Risk:   " + x.why);
      lines.push("  Fix:    " + remediationText(x));
    }

    lines.push("");
    lines.push("----------------------------------------");
    lines.push("Secrets above are masked. Treat every match as compromised and rotate it.");
    return lines.join("\n");
  }

  /* ------------------------------------------------------------------ *
   * Example blob — OBVIOUSLY FAKE but format-valid secrets so first-time
   * users immediately see the tool work.
   * ------------------------------------------------------------------ */
  // Each fake value is assembled from fragments at runtime so this source file
  // contains NO complete secret literal. That stops upstream secret scanners
  // (e.g. GitHub push protection) from blocking this repo on its own demo data,
  // while LeakCheck still sees the full strings once they land in the textarea.
  var EXAMPLE = [
    "# .env.production  (example — these are well-known FAKE test values)",
    "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "STRIPE_SECRET_KEY=" + "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "GITHUB_TOKEN=" + "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    "OPENAI_API_KEY=" + "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345AbCdEf",
    "GOOGLE_API_KEY=" + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
    "DATABASE_URL=postgres://appuser:" + "s3cr3tP@ss" + "@db.example.com:5432/app",
    'const authHeader = "Authorization: Bearer ' + "sk-" + 'aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";',
    "",
    "-----BEGIN " + "PRIVATE KEY-----",
    "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAq3FAKEexampleKEY",
    "do0NOTuseThisKEYitISjustAplaceholderFORtheDEMOscanXXXXXXXXXXXXXX",
    "-----END " + "PRIVATE KEY-----"
  ].join("\n");

  /* ------------------------------------------------------------------ *
   * Wire-up.
   * ------------------------------------------------------------------ */
  function init() {
    var form = document.getElementById("scan-form");
    var textarea = document.getElementById("code");
    var results = document.getElementById("results");
    var exampleBtn = document.getElementById("example-btn");
    var clearBtn = document.getElementById("clear-btn");

    if (!form || !textarea || !results) return; // shell not present

    // Dedicated aria-live region owns scan announcements. #results itself is a
    // labelled (non-live) region so the two don't double-announce.
    var liveRegion = document.getElementById("scan-status");
    if (!liveRegion) {
      liveRegion = el("div", "sr-only");
      liveRegion.id = "scan-status";
      liveRegion.setAttribute("aria-live", "polite");
      liveRegion.setAttribute("role", "status");
      results.parentNode.insertBefore(liveRegion, results);
    }

    var lastFindings = [];

    // Copy handler bound to whatever the most recent scan produced. The button
    // is created inside render(); this is wired to it on every render.
    function handleCopy(btn) {
      var report = buildReport(lastFindings); // masked
      copyReport(report, btn);
    }

    function runScan() {
      var text = textarea.value || "";
      lastFindings = scan(text);
      render(lastFindings, results, liveRegion, handleCopy);
      // Move keyboard focus to the results region so keyboard/AT users land on
      // the output instead of having to tab through empty space.
      if (typeof results.focus === "function") results.focus();
      // Bring results into view without jumping past the page on small screens.
      if (typeof results.scrollIntoView === "function") {
        results.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      runScan();
    });

    if (exampleBtn) {
      exampleBtn.addEventListener("click", function (e) {
        e.preventDefault();
        textarea.value = EXAMPLE;
        textarea.focus();
        runScan();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", function (e) {
        e.preventDefault();
        textarea.value = "";
        lastFindings = [];
        results.textContent = "";
        results.hidden = true;
        announce(liveRegion, "Cleared. Paste code and scan again.");
        textarea.focus();
      });
    }
  }

  /* Clipboard copy — local only, no network. Falls back to a hidden
   * textarea + execCommand when the async clipboard API is unavailable. */
  function copyReport(text, btn) {
    var original = btn.getAttribute("data-label") || btn.textContent;
    btn.setAttribute("data-label", original);

    function done(ok) {
      btn.textContent = ok ? "Copied ✓" : "Copy failed";
      setTimeout(function () { btn.textContent = original; }, 1800);
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { done(true); },
        function () { fallbackCopy(text, done); }
      );
    } else {
      fallbackCopy(text, done);
    }
  }

  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand && document.execCommand("copy");
      document.body.removeChild(ta);
      done(!!ok);
    } catch (err) {
      done(false);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
