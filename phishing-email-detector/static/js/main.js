/**
 * Phishing Email Detector - Frontend Interaction Controller
 * Handles scanning, dynamic DOM updates, risk meter animation, and history logs.
 */

document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("email-scan-form");
    const scanBtn = document.getElementById("btn-scan");
    const scanSpinner = document.getElementById("scan-spinner");
    const scanBtnText = document.getElementById("scan-btn-text");
    const resultsContainer = document.getElementById("results-container");
    const resultsPlaceholder = document.getElementById("results-placeholder");
    const clearHistoryBtn = document.getElementById("btn-clear-history");
    const historyTableBody = document.getElementById("history-table-body");
    const sampleButtons = document.querySelectorAll(".btn-load-sample");

    // Cache preset samples locally for instantaneous response
    let cachedSamples = null;

    // Fetch preset email samples from backend
    fetch("/api/samples")
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                cachedSamples = data.samples;
            }
        })
        .catch(err => console.warn("Could not pre-fetch samples:", err));

    // Handle Quick Sample Email loading
    sampleButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const sampleType = btn.getAttribute("data-sample");
            if (!cachedSamples || !cachedSamples[sampleType]) return;

            const sample = cachedSamples[sampleType];
            document.getElementById("input-sender").value = sample.sender || "";
            document.getElementById("input-reply-to").value = sample.reply_to || "";
            document.getElementById("input-subject").value = sample.subject || "";
            document.getElementById("input-headers").value = sample.headers || "";
            document.getElementById("input-body").value = sample.body || "";

            // Highlight the form briefly
            const formCard = document.getElementById("scanner-card");
            formCard.style.borderColor = "var(--accent-blue)";
            setTimeout(() => {
                formCard.style.borderColor = "var(--border-color)";
            }, 600);
        });
    });

    // Form Submission
    scanForm.addEventListener("submit", async (e) => {
        e.preventDefault();

        const sender = document.getElementById("input-sender").value.trim();
        const replyTo = document.getElementById("input-reply-to").value.trim();
        const subject = document.getElementById("input-subject").value.trim();
        const headers = document.getElementById("input-headers").value.trim();
        const body = document.getElementById("input-body").value.trim();
        const checkThreatIntel = document.getElementById("check-threat-intel").checked;

        if (!body && !subject) {
            alert("Please provide at least an email subject or body text to analyze.");
            return;
        }

        // Set Loading State
        setLoading(true);

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    sender: sender,
                    reply_to: replyTo,
                    subject: subject,
                    headers: headers,
                    body: body,
                    check_threat_intel: checkThreatIntel
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Failed to analyze email.");
            }

            // Render Scan Results
            renderResults(data);

            // Add row to scan history table
            prependHistoryRow(data, subject || "(No Subject)");

        } catch (err) {
            console.error("Scan error:", err);
            const msg = err.message || "Unknown error occurred.";
            alert("Error analyzing email: " + msg +
                "\n\nIf this keeps happening, please check the browser console (F12) for details.");
        } finally {
            setLoading(false);
        }
    });

    // Clear History Button
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to clear all scan history?")) return;

            try {
                const res = await fetch("/api/clear-history", { method: "POST" });
                const json = await res.json();
                if (json.success) {
                    historyTableBody.innerHTML = `
                        <tr>
                            <td colspan="7" class="text-center text-muted py-4">
                                No scan history available. Run an email scan to log audit results.
                            </td>
                        </tr>
                    `;
                }
            } catch (err) {
                console.error("Failed to clear history:", err);
            }
        });
    }

    function setLoading(isLoading) {
        if (isLoading) {
            scanBtn.disabled = true;
            scanSpinner.classList.remove("d-none");
            scanBtnText.textContent = "Analyzing Threat Vector...";
        } else {
            scanBtn.disabled = false;
            scanSpinner.classList.add("d-none");
            scanBtnText.textContent = "Scan Email Content";
        }
    }

    function renderResults(data) {
        // Hide placeholder and reveal results card
        if (resultsPlaceholder) resultsPlaceholder.classList.add("d-none");
        resultsContainer.classList.remove("d-none");

        // Classification & Risk Badge
        const badgeEl = document.getElementById("res-classification-badge");
        badgeEl.textContent = data.classification;
        badgeEl.className = ""; // reset
        if (data.classification === "Phishing") {
            badgeEl.className = "badge-phishing";
        } else if (data.classification === "Suspicious") {
            badgeEl.className = "badge-suspicious";
        } else {
            badgeEl.className = "badge-legitimate";
        }

        // Risk Level Text & Timestamp
        document.getElementById("res-risk-level").textContent = data.risk_level;
        document.getElementById("res-timestamp").textContent = data.timestamp;

        // Composite Risk Score & Progress Meter
        const score = data.composite_score;
        document.getElementById("res-composite-score").textContent = score + " / 100";
        const meterBar = document.getElementById("res-meter-bar");
        meterBar.style.width = score + "%";
        meterBar.className = "risk-progress-bar";
        if (score >= 65) {
            meterBar.classList.add("danger");
        } else if (score >= 35) {
            meterBar.classList.add("warning");
        } else {
            meterBar.classList.add("success");
        }

        // Machine Learning Score Card
        document.getElementById("res-ml-prob").textContent = data.machine_learning.phishing_probability + "%";
        document.getElementById("res-ml-model").textContent = data.machine_learning.model_name;
        document.getElementById("res-ml-class").textContent = data.machine_learning.predicted_class;

        // Email Header Security Findings
        const headerAuth = data.header_analysis;
        renderHeaderAuthentication(headerAuth);

        // URL Security Findings
        renderUrlAnalysis(data.url_analysis);

        // Linguistic Indicators
        renderLinguisticAnalysis(data.linguistic_analysis);

        // Security Recommendations
        const recsContainer = document.getElementById("res-recommendations-list");
        recsContainer.innerHTML = "";
        data.recommendations.forEach(rec => {
            const li = document.createElement("li");
            li.className = "mb-1 text-slate-300";
            li.textContent = rec;
            recsContainer.appendChild(li);
        });

        // Scroll to results smoothly on mobile
        if (window.innerWidth < 992) {
            resultsContainer.scrollIntoView({ behavior: "smooth" });
        }
    }

    function renderHeaderAuthentication(hdr) {
        const setBadge = (elementId, status) => {
            const el = document.getElementById(elementId);
            el.textContent = status;
            el.className = "badge";
            const s = (status || "").toLowerCase();
            if (s === "pass") {
                el.classList.add("bg-success");
            } else if (s === "fail" || s === "softfail") {
                el.classList.add("bg-danger");
            } else if (s.includes("unverified") || s === "neutral") {
                el.classList.add("bg-warning", "text-dark");
            } else {
                el.classList.add("bg-secondary");
            }
        };

        setBadge("res-spf-status", hdr.spf_status);
        setBadge("res-dkim-status", hdr.dkim_status);
        setBadge("res-dmarc-status", hdr.dmarc_status);

        // Mismatches and Spoofing Alerts
        const findingsList = document.getElementById("res-header-findings");
        findingsList.innerHTML = "";

        if (hdr.findings && hdr.findings.length > 0) {
            hdr.findings.forEach(finding => {
                const item = document.createElement("div");
                item.className = "indicator-item danger";
                item.innerHTML = `<i class="bi bi-exclamation-triangle-fill me-2 text-danger"></i>${finding}`;
                findingsList.appendChild(item);
            });
        } else {
            const item = document.createElement("div");
            item.className = "indicator-item success";
            item.innerHTML = `<i class="bi bi-shield-check me-2 text-success"></i>No anomalies detected in provided email headers.`;
            findingsList.appendChild(item);
        }
    }

    function renderUrlAnalysis(urlData) {
        const urlContainer = document.getElementById("res-urls-container");
        const urlCountBadge = document.getElementById("res-url-count-badge");
        urlCountBadge.textContent = `${urlData.suspicious_url_count} Suspicious / ${urlData.total_urls} Total`;

        if (!urlData.has_urls) {
            urlContainer.innerHTML = `
                <div class="indicator-item">
                    <i class="bi bi-info-circle me-2 text-info"></i>No hyperlinks detected in email text.
                </div>
            `;
            return;
        }

        let html = '<div class="table-responsive"><table class="table table-cyber mb-0">';
        html += `
            <thead>
                <tr>
                    <th>Extracted Target URL</th>
                    <th>Risk Score</th>
                    <th>Security Observations & Heuristics</th>
                </tr>
            </thead>
            <tbody>
        `;

        urlData.urls_details.forEach(item => {
            const riskClass = item.risk_score >= 50 ? "text-danger" : (item.risk_score >= 25 ? "text-warning" : "text-success");
            const flagsHtml = item.flags.length > 0
                ? item.flags.map(f => `<span class="badge bg-dark border border-danger text-danger-emphasis me-1 mb-1">${f}</span>`).join(" ")
                : `<span class="text-success"><i class="bi bi-check-circle me-1"></i>No high-risk URL patterns</span>`;

            html += `
                <tr>
                    <td>
                        <code class="text-break text-cyan" style="color: #38bdf8;">${escapeHtml(item.url)}</code>
                        ${item.hostname ? `<div class="small text-muted">Host: ${escapeHtml(item.hostname)}</div>` : ""}
                    </td>
                    <td>
                        <span class="fw-bold ${riskClass}">${item.risk_score}/100</span>
                    </td>
                    <td>${flagsHtml}</td>
                </tr>
            `;
        });

        html += '</tbody></table></div>';
        urlContainer.innerHTML = html;
    }

    function renderLinguisticAnalysis(lingData) {
        const lingContainer = document.getElementById("res-linguistic-container");
        const keywords = lingData.matched_urgency_keywords || [];

        let kwHtml = "";
        if (keywords.length > 0) {
            kwHtml = keywords.map(kw => `<span class="badge bg-secondary me-1 mb-1 text-light border border-secondary">${kw}</span>`).join(" ");
        } else {
            kwHtml = `<span class="text-muted small">None detected</span>`;
        }

        lingContainer.innerHTML = `
            <div class="row g-2">
                <div class="col-6 col-md-3">
                    <div class="stat-pill">
                        <span class="stat-label">Urgency Keywords</span>
                        <span class="stat-value fs-6">${lingData.urgency_keyword_count}</span>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="stat-pill">
                        <span class="stat-label">Uppercase Ratio</span>
                        <span class="stat-value fs-6">${(lingData.uppercase_ratio * 100).toFixed(1)}%</span>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="stat-pill">
                        <span class="stat-label">Exclamations</span>
                        <span class="stat-value fs-6">${lingData.exclamation_count}</span>
                    </div>
                </div>
                <div class="col-6 col-md-3">
                    <div class="stat-pill">
                        <span class="stat-label">Linguistic Score</span>
                        <span class="stat-value fs-6">${lingData.linguistic_risk_score}/100</span>
                    </div>
                </div>
            </div>
            <div class="mt-2 small">
                <strong class="text-muted">Detected Panic / Urgency Triggers:</strong>
                <div class="mt-1">${kwHtml}</div>
            </div>
        `;
    }

    function prependHistoryRow(data, subject) {
        // If empty row exists, remove it
        const emptyRow = historyTableBody.querySelector("td[colspan]");
        if (emptyRow) {
            historyTableBody.innerHTML = "";
        }

        const tr = document.createElement("tr");
        const badgeColor = data.classification === "Phishing" ? "text-danger" : (data.classification === "Suspicious" ? "text-warning" : "text-success");

        tr.innerHTML = `
            <td class="text-muted small">${data.timestamp}</td>
            <td class="fw-semibold text-truncate" style="max-width: 180px;" title="${escapeHtml(subject)}">${escapeHtml(subject)}</td>
            <td><span class="fw-bold ${badgeColor}">${data.classification}</span></td>
            <td><span class="fw-bold">${data.composite_score}</span></td>
            <td>${data.machine_learning.phishing_probability}%</td>
            <td>${data.url_analysis.total_urls} (${data.url_analysis.suspicious_url_count} flagged)</td>
            <td class="small text-muted text-truncate" style="max-width: 200px;">${escapeHtml(data.risk_level)}</td>
        `;

        historyTableBody.insertBefore(tr, historyTableBody.firstChild);
    }

    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
