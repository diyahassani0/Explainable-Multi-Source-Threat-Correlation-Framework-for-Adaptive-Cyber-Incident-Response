/**
 * Explainable Multi-Source Threat Correlation Framework
 * Frontend Application Controller (JavaScript)
 */

const API_BASE = "";

// Global App State
const state = {
    activeTab: "dashboard",
    currentIncidentId: 1,
    currentCampaignId: 1,
    logsPage: 1,
    logsPageSize: 20,
    incidentsPage: 1,
    incidentsPageSize: 15,
    charts: {},
    networkGraph: null,
    pendingSoarAction: null,
};

// Initialize Application on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initCharts();
    loadDashboardData();
    fetchLogs(1);
    fetchCorrelations();
    fetchMLMetrics();
    fetchGlobalXAI();
    fetchPlaybooks();
    fetchSoarActions();
    loadIncidentInvestigation(1);
    fetchIncidents(1);
});

/* =========================================================================
   1. NAVIGATION & TABS
   ========================================================================= */

function initNavigation() {
    const navItems = document.querySelectorAll(".sidebar-menu .nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const tabName = item.getAttribute("data-tab");
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    state.activeTab = tabName;

    // Update sidebar active class
    document.querySelectorAll(".sidebar-menu .nav-item").forEach(item => {
        if (item.getAttribute("data-tab") === tabName) {
            item.classList.add("active");
        } else {
            item.classList.remove("active");
        }
    });

    // Update tab panes
    document.querySelectorAll(".tab-pane").forEach(pane => {
        pane.classList.remove("active");
    });
    const targetPane = document.getElementById(`tab-${tabName}`);
    if (targetPane) {
        targetPane.classList.add("active");
    }

    // Update topbar heading
    const headings = {
        dashboard: ["Security Operations Dashboard", "Real-Time Telemetry & Threat Metrics"],
        logs: ["Multi-Source Security Telemetry", "Log Collection, Normalization & Ingestion"],
        preprocessing: ["Data Preprocessing & Methodology", "Feature Engineering & Sector Risk Formulation"],
        correlation: ["Graph-Based Threat Correlation", "Multi-Source Alert Graph & Attack Chain Progressions"],
        ml: ["Machine Learning Model Evaluation", "XGBoost Classifier & Holdout Evaluation Metrics"],
        xai: ["Explainable AI (SHAP)", "TreeExplainer Feature Attribution & Game-Theoretic Rationales"],
        soar: ["Adaptive Incident Response (SOAR)", "Automated Threat Containment & Simulated Playbooks"],
        investigation: ["Incident Investigation Workbench", "Deep Forensic Drill-Down & Analyst Audit Trail"],
        reports: ["Reports, Analytics & Telemetry Export", "Compliance Export & Executive Incident Reports"],
    };

    const [heading, subheading] = headings[tabName] || ["Security Dashboard", "Threat Analysis"];
    document.getElementById("page-heading").innerText = heading;
    document.getElementById("page-subheading").innerText = subheading;

    // Redraw graphs if tab is correlation
    if (tabName === "correlation" && state.networkGraph) {
        setTimeout(() => {
            state.networkGraph.fit();
        }, 150);
    }
}

/* =========================================================================
   2. CHARTS INITIALIZATION & DASHBOARD
   ========================================================================= */

function initCharts() {
    // 1. Severity Distribution Donut
    const ctxSev = document.getElementById("chart-severity")?.getContext("2d");
    if (ctxSev) {
        state.charts.severity = new Chart(ctxSev, {
            type: "doughnut",
            data: {
                labels: ["Critical", "High", "Medium", "Low"],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ["#DC2626", "#EA580C", "#D97706", "#2563EB"],
                    borderWidth: 2,
                    borderColor: "#FFFFFF",
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "right", labels: { boxWidth: 12, font: { size: 11, family: "Inter" } } },
                },
                cutout: "65%",
            }
        });
    }

    // 2. Log Sources Bar Chart
    const ctxSrc = document.getElementById("chart-sources")?.getContext("2d");
    if (ctxSrc) {
        state.charts.sources = new Chart(ctxSrc, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Normalized Events",
                    data: [],
                    backgroundColor: "#1E3E62",
                    borderRadius: 4,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, grid: { color: "#F1F5F9" } },
                    x: { grid: { display: false } }
                }
            }
        });
    }

    // 3. Category Financial Loss Horizontal Bar
    const ctxCat = document.getElementById("chart-category-loss")?.getContext("2d");
    if (ctxCat) {
        state.charts.categoryLoss = new Chart(ctxCat, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Loss in INR",
                    data: [],
                    backgroundColor: "#00A8E8",
                    borderRadius: 4,
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: (ctx) => `Loss: INR ${ctx.parsed.x.toLocaleString()}`
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "#F1F5F9" },
                        ticks: { callback: (val) => `₹${(val / 1e5).toFixed(1)}L` }
                    },
                    y: { grid: { display: false } }
                }
            }
        });
    }

    // 4. Global SHAP Feature Importance
    const ctxShap = document.getElementById("chart-shap-global")?.getContext("2d");
    if (ctxShap) {
        state.charts.shap = new Chart(ctxShap, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Mean |SHAP Value| Impact",
                    data: [],
                    backgroundColor: "#0B192C",
                    borderRadius: 4,
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, grid: { color: "#F1F5F9" } },
                    y: { grid: { display: false } }
                }
            }
        });
    }
}

async function loadDashboardData() {
    try {
        const res = await fetch(`${API_BASE}/api/dashboard/summary`);
        const data = await res.json();

        // Update KPIs
        document.getElementById("kpi-total-events").innerText = Number(data.metrics.total_security_events).toLocaleString();
        document.getElementById("kpi-total-incidents").innerText = Number(data.metrics.total_incidents).toLocaleString();
        document.getElementById("kpi-critical-incidents").innerText = Number(data.metrics.critical_incidents).toLocaleString();
        document.getElementById("kpi-correlated-alerts").innerText = Number(data.metrics.active_campaigns).toLocaleString();
        document.getElementById("kpi-false-positives").innerText = Number(data.metrics.false_positives).toLocaleString();

        // Update Severity Chart
        if (state.charts.severity && data.severity_distribution) {
            state.charts.severity.data.datasets[0].data = [
                data.severity_distribution.Critical || 0,
                data.severity_distribution.High || 0,
                data.severity_distribution.Medium || 0,
                data.severity_distribution.Low || 0,
            ];
            state.charts.severity.update();
        }

        // Update Sources Chart
        if (state.charts.sources && data.log_source_distribution) {
            state.charts.sources.data.labels = Object.keys(data.log_source_distribution);
            state.charts.sources.data.datasets[0].data = Object.values(data.log_source_distribution);
            state.charts.sources.update();
        }

        // Update Category Financial Loss Chart
        if (state.charts.categoryLoss && data.category_loss) {
            state.charts.categoryLoss.data.labels = data.category_loss.map(c => c.category);
            state.charts.categoryLoss.data.datasets[0].data = data.category_loss.map(c => c.total_loss);
            state.charts.categoryLoss.update();
        }

        // Update Recent Alerts Table
        const tbody = document.getElementById("recent-alerts-table-body");
        if (tbody && data.recent_alerts) {
            tbody.innerHTML = data.recent_alerts.map(a => `
                <tr>
                    <td><strong>#${a.id}</strong></td>
                    <td>${escapeHtml(a.incident_type)}</td>
                    <td>${escapeHtml(a.category)} (${escapeHtml(a.city)})</td>
                    <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
                    <td><button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="investigateIncident(${a.id})">Investigate</button></td>
                </tr>
            `).join("");
        }
    } catch (err) {
        console.error("Failed to load dashboard data:", err);
    }
}

function refreshDashboardData() {
    loadDashboardData();
    showToast("Dashboard synchronized with real-time SIEM telemetry.", "info");
}

/* =========================================================================
   3. MULTI-SOURCE LOG INGESTION & NORMALIZATION
   ========================================================================= */

let searchLogTimeout = null;
function debounceLogSearch() {
    clearTimeout(searchLogTimeout);
    searchLogTimeout = setTimeout(() => {
        fetchLogs(1);
    }, 300);
}

async function fetchLogs(page = 1) {
    state.logsPage = page;
    const source = document.getElementById("log-filter-source")?.value || "All";
    const search = document.getElementById("log-search-input")?.value || "";

    const url = new URL(`${API_BASE}/api/logs`, window.location.origin);
    url.searchParams.set("page", page);
    url.searchParams.set("page_size", state.logsPageSize);
    if (source !== "All") url.searchParams.set("source", source);
    if (search) url.searchParams.set("search", search);

    try {
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById("logs-table-body");

        if (data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #94A3B8;">No logs found matching criteria.</td></tr>`;
        } else {
            tbody.innerHTML = data.logs.map(l => `
                <tr>
                    <td><code>${l.log_id}</code></td>
                    <td style="font-family: monospace; font-size: 11px;">${l.timestamp}</td>
                    <td><span class="badge badge-source">${l.log_source}</span></td>
                    <td>${escapeHtml(l.event_type)}</td>
                    <td style="font-family: monospace; font-size: 11px;">${l.source_ip} &rarr; ${l.dest_ip}</td>
                    <td><code>${l.action_taken || "NONE"}</code></td>
                    <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 11px;">${escapeHtml(l.raw_log)}</td>
                </tr>
            `).join("");
        }

        document.getElementById("logs-pagination-info").innerText =
            `Showing page ${data.page} of ${data.total_pages || 1} (${data.total} total logs)`;
        document.getElementById("btn-prev-log").disabled = data.page <= 1;
        document.getElementById("btn-next-log").disabled = data.page >= data.total_pages;
    } catch (err) {
        console.error("Failed to fetch logs:", err);
    }
}

function changeLogPage(delta) {
    fetchLogs(state.logsPage + delta);
}

// Live Raw Log Normalization Sandbox
async function testNormalizeLog() {
    const raw = document.getElementById("raw-log-input").value;
    if (!raw.trim()) {
        showToast("Please provide raw log text.", "warning");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/api/logs/normalize`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ raw_log: raw })
        });
        const data = await res.json();
        document.getElementById("normalized-log-output").innerText = JSON.stringify(data, null, 2);
        showToast("Raw log normalized into Common Event Schema.", "success");
    } catch (err) {
        console.error("Failed to normalize log:", err);
    }
}

function loadSampleLog(type) {
    const samples = {
        snort: "[**] [1:2029381:2] ET EXPLOIT Suspicious Apache Struts OGNL RCE [**] [Priority: 1] {194.26.29.112:51234 -> 10.10.1.20:8080}",
        windows: "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID></System><EventData><Data Name='TargetUserName'>Administrator</Data><Data Name='IpAddress'>185.220.101.5</Data></EventData></Event>",
    };
    document.getElementById("raw-log-input").value = samples[type] || "";
    testNormalizeLog();
}

/* =========================================================================
   4. THREAT CORRELATION & ATTACK CHAINS (VIS.JS)
   ========================================================================= */

async function fetchCorrelations() {
    try {
        const res = await fetch(`${API_BASE}/api/correlations`);
        const data = await res.json();
        const selector = document.getElementById("correlation-campaign-selector");

        if (data.clusters.length > 0) {
            selector.innerHTML = data.clusters.map(c => `
                <option value="${c.cluster_id}">${c.cluster_name} (${c.incident_count} events - ${c.severity})</option>
            `).join("");
            state.currentCampaignId = data.clusters[0].cluster_id;
            loadSelectedCampaignGraph();
        } else {
            selector.innerHTML = `<option value="">No campaigns available</option>`;
        }
    } catch (err) {
        console.error("Failed to fetch correlations:", err);
    }
}

async function loadSelectedCampaignGraph() {
    const clusterId = document.getElementById("correlation-campaign-selector")?.value || state.currentCampaignId;
    state.currentCampaignId = clusterId;

    try {
        const res = await fetch(`${API_BASE}/api/correlations/${clusterId}/graph`);
        const graphData = await res.json();

        // Update Textual Explanation
        document.getElementById("correlation-explanation-text").innerText = graphData.explanation;

        // Render Vis.js Network
        const container = document.getElementById("network-graph-container");
        const data = {
            nodes: new vis.DataSet(graphData.nodes),
            edges: new vis.DataSet(graphData.edges),
        };

        const options = {
            nodes: {
                borderWidth: 2,
                shadow: true,
                font: { face: "Inter", size: 12 },
            },
            edges: {
                smooth: { type: "cubicBezier", forceDirection: "horizontal" },
                font: { size: 10, face: "Inter", align: "middle", background: "#0B1424", strokeWidth: 0, color: "#94A3B8" },
                arrows: { to: { scaleFactor: 0.8 } }
            },
            physics: {
                barnesHut: { gravitationalConstant: -3500, centralGravity: 0.3, springLength: 120 },
                stabilization: { iterations: 120 },
            },
            interaction: {
                hover: true,
                tooltipDelay: 100,
            }
        };

        if (state.networkGraph) {
            state.networkGraph.destroy();
        }
        state.networkGraph = new vis.Network(container, data, options);
    } catch (err) {
        console.error("Failed to load correlation graph:", err);
    }
}

/* =========================================================================
   5. MACHINE LEARNING & SHAP XAI
   ========================================================================= */

async function fetchMLMetrics() {
    try {
        const res = await fetch(`${API_BASE}/api/ml/metrics`);
        const data = await res.json();

        document.getElementById("ml-accuracy").innerText = `${(data.accuracy * 100).toFixed(1)}%`;
        document.getElementById("ml-precision").innerText = `${(data.precision_weighted * 100).toFixed(1)}%`;
        document.getElementById("ml-recall").innerText = `${(data.recall_weighted * 100).toFixed(1)}%`;
        document.getElementById("ml-f1").innerText = `${(data.f1_weighted * 100).toFixed(1)}%`;

        // Render Confusion Matrix
        const cmBody = document.getElementById("confusion-matrix-body");
        if (cmBody && data.confusion_matrix) {
            const labels = data.confusion_matrix.labels;
            const matrix = data.confusion_matrix.matrix;
            cmBody.innerHTML = labels.map((lbl, rIdx) => `
                <tr>
                    <td><strong>Actual ${lbl}</strong></td>
                    ${matrix[rIdx].map((val, cIdx) => `
                        <td style="background-color: ${rIdx === cIdx ? 'rgba(34, 197, 94, 0.15)' : val > 0 ? 'rgba(239, 68, 68, 0.08)' : 'transparent'}; font-weight: ${rIdx === cIdx ? '700' : '400'};">
                            ${val}
                        </td>
                    `).join("")}
                </tr>
            `).join("");
        }

        // Render Baseline comparison
        const compBody = document.getElementById("baseline-comparison-body");
        if (compBody && data.baseline_comparison) {
            compBody.innerHTML = data.baseline_comparison.map(m => `
                <tr>
                    <td><strong>${m.model}</strong> <br><small style="color: #64748B;">${m.type}</small></td>
                    <td>${(m.accuracy * 100).toFixed(1)}%</td>
                    <td>${(m.f1_score * 100).toFixed(1)}%</td>
                    <td><span class="badge ${m.status.includes('Active') ? 'badge-low' : 'badge-source'}">${m.status}</span></td>
                </tr>
            `).join("");
        }
    } catch (err) {
        console.error("Failed to fetch ML metrics:", err);
    }
}

async function runLivePrediction() {
    const payload = {
        Incident_Type: document.getElementById("pred-input-type").value,
        Category: document.getElementById("pred-input-category").value,
        Amount_Lost_INR: Number(document.getElementById("pred-input-amount").value),
        City: document.getElementById("pred-input-city").value,
        Year: 2024,
        Day: 15,
    };

    try {
        const res = await fetch(`${API_BASE}/api/ml/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        document.getElementById("pred-result-severity").innerText = data.predicted_severity;
        const badge = document.getElementById("pred-result-confidence-badge");
        badge.className = `badge badge-${data.predicted_severity.toLowerCase()}`;
        badge.innerText = `Confidence ${(data.confidence * 100).toFixed(1)}%`;
        document.getElementById("pred-result-narrative").innerText = data.explanation_narrative;

        showToast(`Classified as ${data.predicted_severity} (${(data.confidence * 100).toFixed(1)}% confidence).`, "info");
    } catch (err) {
        console.error("Failed to predict severity:", err);
    }
}

async function fetchGlobalXAI() {
    try {
        const res = await fetch(`${API_BASE}/api/xai/global`);
        const data = await res.json();

        if (state.charts.shap && data.feature_importance) {
            state.charts.shap.data.labels = data.feature_importance.map(f => f.feature);
            state.charts.shap.data.datasets[0].data = data.feature_importance.map(f => f.importance);
            state.charts.shap.update();
        }
    } catch (err) {
        console.error("Failed to fetch global XAI:", err);
    }
}

/* =========================================================================
   6. ADAPTIVE INCIDENT RESPONSE (SOAR)
   ========================================================================= */

async function fetchPlaybooks() {
    try {
        const res = await fetch(`${API_BASE}/api/soar/playbooks`);
        const data = await res.json();
        const container = document.getElementById("playbooks-container");

        if (container && data.playbooks) {
            container.innerHTML = data.playbooks.map(pb => `
                <div class="card" style="margin-bottom: 0;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                        <span class="badge badge-source">${pb.playbook_id}</span>
                        <span class="badge badge-medium">Risk: ${pb.blast_radius}</span>
                    </div>
                    <h4 style="font-size: 14px; font-weight: 700; color: var(--navy-primary); margin-bottom: 6px;">${pb.name}</h4>
                    <p style="font-size: 12px; color: #475569; line-height: 1.4; margin-bottom: 12px;">${pb.description}</p>
                    <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px;">
                        <strong>Target:</strong> ${pb.target_type} | <strong>Action:</strong> ${pb.default_action}
                    </div>
                    <pre class="log-snippet" style="font-size: 10px; margin-bottom: 12px;">${escapeHtml(pb.cli_command)}</pre>
                    <button class="btn-primary" style="width: 100%; justify-content: center;" onclick="quickLaunchPlaybook('${pb.playbook_id}', '${escapeHtml(pb.name)}', '${escapeHtml(pb.default_action)}')">
                        <i class="fa-solid fa-play"></i> Test Playbook (Dry-Run)
                    </button>
                </div>
            `).join("");
        }
    } catch (err) {
        console.error("Failed to fetch playbooks:", err);
    }
}

async function fetchSoarActions() {
    try {
        const res = await fetch(`${API_BASE}/api/soar/actions`);
        const data = await res.json();
        const tbody = document.getElementById("soar-actions-history-body");

        if (tbody) {
            if (data.actions.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #94A3B8;">No response actions executed yet.</td></tr>`;
            } else {
                tbody.innerHTML = data.actions.map(a => `
                    <tr>
                        <td><strong>#${a.action_id}</strong></td>
                        <td>${a.incident_id ? `#${a.incident_id}` : "Global"}</td>
                        <td><strong>${escapeHtml(a.action_type)}</strong></td>
                        <td><code>${escapeHtml(a.target_entity)}</code></td>
                        <td><span class="badge badge-source">${escapeHtml(a.playbook_name || "PB-102")}</span></td>
                        <td><span class="badge badge-low">${a.execution_mode}</span></td>
                        <td><span class="badge badge-critical" style="background: #F0FDF4; color: #15803D; border-color: #86EFAC;">${a.status}</span></td>
                        <td style="font-size: 11px; font-family: monospace;">${a.executed_at}</td>
                    </tr>
                `).join("");
            }
        }
    } catch (err) {
        console.error("Failed to fetch SOAR actions:", err);
    }
}

function promptSimulatedActionExecution() {
    if (!state.pendingSoarAction) return;

    const action = state.pendingSoarAction;
    document.getElementById("modal-playbook-name").innerText = `${action.playbook_id} (${action.playbook_name})`;
    document.getElementById("modal-action-type").innerText = action.recommended_action;
    document.getElementById("modal-target-entity").innerText = action.target_entity;
    document.getElementById("modal-blast-radius").innerText = action.blast_radius;

    document.getElementById("soar-confirm-modal").classList.add("active");
}

function quickLaunchPlaybook(pbId, name, defaultAction) {
    state.pendingSoarAction = {
        incident_id: state.currentIncidentId,
        playbook_id: pbId,
        playbook_name: name,
        recommended_action: defaultAction,
        target_entity: "198.51.100.42",
        blast_radius: "Low",
    };
    promptSimulatedActionExecution();
}

function closeSoarModal() {
    document.getElementById("soar-confirm-modal").classList.remove("active");
}

async function confirmExecuteSoarAction() {
    if (!state.pendingSoarAction) return;

    const payload = {
        incident_id: state.pendingSoarAction.incident_id,
        playbook_id: state.pendingSoarAction.playbook_id,
        action_type: state.pendingSoarAction.recommended_action,
        target_entity: state.pendingSoarAction.target_entity,
        confirmed: true,
        simulated: true,
        analyst_id: "SOC_Analyst_Lead",
    };

    try {
        const res = await fetch(`${API_BASE}/api/soar/execute`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        closeSoarModal();
        if (data.success) {
            showToast(data.message, "success");
            fetchSoarActions();
            loadIncidentInvestigation(state.currentIncidentId);
        } else {
            showToast(data.message, "danger");
        }
    } catch (err) {
        console.error("Failed to execute SOAR action:", err);
    }
}

/* =========================================================================
   7. INCIDENT INVESTIGATION WORKBENCH
   ========================================================================= */

function investigateIncident(incId) {
    state.currentIncidentId = incId;
    switchTab("investigation");
    loadIncidentInvestigation(incId);
}

async function loadIncidentInvestigation(incId = 1) {
    state.currentIncidentId = incId;

    try {
        const res = await fetch(`${API_BASE}/api/incidents/${incId}`);
        const data = await res.json();
        const inc = data.incident;

        // Update selector
        const selector = document.getElementById("investigation-incident-selector");
        if (selector && selector.value != incId) {
            selector.value = incId;
        }

        // Summary Cards
        const sevBadge = document.getElementById("inv-severity-badge");
        sevBadge.className = `badge badge-${inc.severity.toLowerCase()}`;
        sevBadge.innerText = inc.severity;
        document.getElementById("inv-predicted-text").innerText = `Model: ${inc.predicted_severity} (${(inc.confidence_score * 100).toFixed(0)}%)`;
        document.getElementById("inv-amount-loss").innerText = `₹${Number(inc.amount_lost_inr).toLocaleString()}`;
        document.getElementById("inv-type-category").innerText = `${inc.incident_type}`;
        document.getElementById("inv-location-text").innerText = `${inc.category} (${inc.city})`;
        document.getElementById("inv-status-dropdown").value = inc.investigation_status || "New";

        // SHAP Local Impacts
        const xai = data.xai_explanation;
        document.getElementById("inv-xai-narrative").innerText = xai.explanation_narrative;
        const barsContainer = document.getElementById("inv-shap-bars-container");
        barsContainer.innerHTML = xai.feature_impacts.slice(0, 5).map(f => {
            const isPos = f.effect === "Increases Risk";
            return `
                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 2px;">
                        <span><strong>${f.feature}</strong> (${f.raw_value})</span>
                        <span style="color: ${isPos ? '#DC2626' : '#16A34A'}; font-weight: 600;">${f.shap_value > 0 ? '+' : ''}${f.shap_value.toFixed(4)}</span>
                    </div>
                    <div style="height: 6px; background: #E2E8F0; border-radius: 3px; overflow: hidden;">
                        <div style="height: 100%; width: ${Math.min(f.magnitude * 100, 100)}%; background: ${isPos ? '#DC2626' : '#16A34A'};"></div>
                    </div>
                </div>
            `;
        }).join("");

        // SOAR Box
        const soar = data.adaptive_response;
        state.pendingSoarAction = soar;
        document.getElementById("inv-soar-rationale").innerText = soar.rationale;
        document.getElementById("inv-soar-command").innerText = soar.command_template;

        // Connected Logs
        const logsBody = document.getElementById("inv-connected-logs-body");
        if (data.connected_logs.length === 0) {
            logsBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: #94A3B8;">No telemetry attached to this ID.</td></tr>`;
        } else {
            logsBody.innerHTML = data.connected_logs.map(l => `
                <tr>
                    <td><span class="badge badge-source">${l.log_source}</span></td>
                    <td>${escapeHtml(l.event_type)}</td>
                    <td><code>${l.action_taken}</code></td>
                </tr>
            `).join("");
        }

        // Analyst Notes History
        const notesContainer = document.getElementById("inv-notes-history-container");
        if (data.analyst_notes.length === 0) {
            notesContainer.innerHTML = `<p style="font-size: 12px; color: #94A3B8; text-align: center; padding: 12px;">No notes recorded yet.</p>`;
        } else {
            notesContainer.innerHTML = data.analyst_notes.map(n => `
                <div style="background: #F8FAFC; border: 1px solid #E2E8F0; padding: 8px 12px; border-radius: 6px; margin-bottom: 6px;">
                    <div style="display: flex; justify-content: space-between; font-size: 10.5px; color: var(--text-muted); margin-bottom: 2px;">
                        <strong>${escapeHtml(n.author)}</strong>
                        <span>${n.created_at}</span>
                    </div>
                    <div style="font-size: 12px; color: #1E293B;">${escapeHtml(n.note_text)}</div>
                </div>
            `).join("");
        }
    } catch (err) {
        console.error("Failed to load incident investigation:", err);
    }
}

function loadIncidentInvestigationDetails() {
    const incId = document.getElementById("investigation-incident-selector").value;
    loadIncidentInvestigation(incId);
}

async function updateCurrentIncidentStatus() {
    const newStatus = document.getElementById("inv-status-dropdown").value;
    try {
        const res = await fetch(`${API_BASE}/api/incidents/${state.currentIncidentId}/status`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`Incident #${state.currentIncidentId} transitioned to ${newStatus}.`, "success");
            loadDashboardData();
        }
    } catch (err) {
        console.error("Failed to update status:", err);
    }
}

async function submitAnalystNote() {
    const input = document.getElementById("inv-note-input");
    const text = input.value.trim();
    if (!text) return;

    try {
        const res = await fetch(`${API_BASE}/api/incidents/${state.currentIncidentId}/notes`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ note_text: text, author: "Lead SOC Analyst" })
        });
        const data = await res.json();
        if (data.success) {
            input.value = "";
            showToast("Analyst note recorded to audit trail.", "info");
            loadIncidentInvestigation(state.currentIncidentId);
        }
    } catch (err) {
        console.error("Failed to add note:", err);
    }
}

function printExecutiveReport() {
    window.open(`${API_BASE}/api/reports/incident/${state.currentIncidentId}/html`, "_blank");
}

/* =========================================================================
   8. REPORTS & ANALYTICS TABLE
   ========================================================================= */

let searchIncTimeout = null;
function debounceIncidentSearch() {
    clearTimeout(searchIncTimeout);
    searchIncTimeout = setTimeout(() => {
        fetchIncidents(1);
    }, 300);
}

async function fetchIncidents(page = 1) {
    state.incidentsPage = page;
    const severity = document.getElementById("report-filter-severity")?.value || "All";
    const status = document.getElementById("report-filter-status")?.value || "All";
    const category = document.getElementById("report-filter-category")?.value || "All";
    const search = document.getElementById("report-search-input")?.value || "";

    const url = new URL(`${API_BASE}/api/incidents`, window.location.origin);
    url.searchParams.set("page", page);
    url.searchParams.set("page_size", state.incidentsPageSize);
    if (severity !== "All") url.searchParams.set("severity", severity);
    if (status !== "All") url.searchParams.set("status", status);
    if (category !== "All") url.searchParams.set("category", category);
    if (search) url.searchParams.set("search", search);

    try {
        const res = await fetch(url);
        const data = await res.json();
        const tbody = document.getElementById("incidents-table-body");

        if (data.incidents.length === 0) {
            tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; color: #94A3B8;">No incidents found.</td></tr>`;
        } else {
            tbody.innerHTML = data.incidents.map(inc => `
                <tr>
                    <td><strong>#${inc.id}</strong></td>
                    <td>${inc.year}</td>
                    <td>Day ${inc.day}</td>
                    <td><strong>${escapeHtml(inc.incident_type)}</strong></td>
                    <td>${escapeHtml(inc.city)}</td>
                    <td>${escapeHtml(inc.category)}</td>
                    <td>₹${Number(inc.amount_lost_inr).toLocaleString()}</td>
                    <td><span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity}</span></td>
                    <td>${inc.predicted_severity || "--"}</td>
                    <td><span class="badge badge-source">${inc.investigation_status}</span></td>
                    <td>
                        <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="window.open('/api/reports/incident/${inc.id}/html', '_blank')">
                            <i class="fa-solid fa-file-pdf"></i>
                        </button>
                    </td>
                </tr>
            `).join("");

            // Also update dropdown in Workbench if needed
            const invSelector = document.getElementById("investigation-incident-selector");
            if (invSelector && invSelector.options.length <= 1) {
                invSelector.innerHTML = data.incidents.map(i => `
                    <option value="${i.id}">#${i.id}: ${i.incident_type} (${i.severity})</option>
                `).join("");
            }
        }

        document.getElementById("incidents-pagination-info").innerText =
            `Showing page ${data.page} of ${data.total_pages || 1} (${data.total} total incidents)`;
        document.getElementById("btn-prev-inc").disabled = data.page <= 1;
        document.getElementById("btn-next-inc").disabled = data.page >= data.total_pages;
    } catch (err) {
        console.error("Failed to fetch incidents:", err);
    }
}

function changeIncidentPage(delta) {
    fetchIncidents(state.incidentsPage + delta);
}

/* =========================================================================
   9. DATASET UPLOAD
   ========================================================================= */

function openUploadModal() {
    document.getElementById("upload-dataset-modal").classList.add("active");
    document.getElementById("upload-status-msg").innerHTML = "";
}

function closeUploadModal() {
    document.getElementById("upload-dataset-modal").classList.remove("active");
}

async function submitDatasetUpload() {
    const fileInput = document.getElementById("dataset-file-input");
    if (!fileInput.files || fileInput.files.length === 0) {
        showToast("Please select a CSV or JSON file.", "warning");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    const statusMsg = document.getElementById("upload-status-msg");
    statusMsg.innerHTML = `<span style="color: var(--accent-blue);">Uploading and validating dataset...</span>`;

    try {
        const res = await fetch(`${API_BASE}/api/logs/upload`, {
            method: "POST",
            body: formData,
        });
        const data = await res.json();

        if (data.success) {
            statusMsg.innerHTML = `<span style="color: #16A34A; font-weight: 600;"><i class="fa-solid fa-check"></i> ${data.message}</span>`;
            showToast(data.message, "success");
            setTimeout(closeUploadModal, 1500);
        } else {
            statusMsg.innerHTML = `<span style="color: #DC2626;"><i class="fa-solid fa-xmark"></i> ${data.error}</span>`;
        }
    } catch (err) {
        statusMsg.innerHTML = `<span style="color: #DC2626;">Failed to upload dataset.</span>`;
    }
}

/* =========================================================================
   10. UTILITIES & TOASTS
   ========================================================================= */

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type === 'danger' ? 'critical' : ''}`;
    toast.innerHTML = `
        <i class="fa-solid fa-${type === 'danger' ? 'triangle-exclamation' : type === 'success' ? 'circle-check' : 'circle-info'}"></i>
        <span>${escapeHtml(message)}</span>
    `;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 250);
    }, 4000);
}

function escapeHtml(str) {
    if (typeof str !== "string") return str;
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
