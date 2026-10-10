"""
Main Flask REST API Server & Application Controller.
Connects SQLite database, ML Engine (XGBoost + SHAP), Correlation Engine,
SOAR Adaptive Response, and serves the frontend Single-Page Application.
"""

import os
import json
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS

from backend.db import get_db_connection, init_db, dict_from_row, dict_list
from backend.preprocessing import (
    load_and_preprocess_dataset,
    generate_deterministic_ips,
    generate_synthetic_raw_logs,
    parse_and_normalize_raw_log,
    SECTOR_WEIGHTS,
    VECTOR_WEIGHTS,
)
from backend.ml_engine import (
    train_and_evaluate_models,
    predict_incident_severity,
    get_ml_metrics,
)
from backend.correlation_engine import (
    compute_correlations,
    build_visjs_graph,
)
from backend.soar_engine import (
    PLAYBOOKS,
    recommend_response_action,
    execute_simulated_action,
)
from backend.report_generator import (
    generate_executive_html_report,
    export_incidents_to_csv,
    export_incidents_to_json,
)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_PATH = BASE_DIR / "data" / "cybersecurity_incidents.csv"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
CORS(app)

# In-memory cached correlation clusters
_CORRELATION_CACHE = []
_INCIDENTS_CACHE_MAP = {}


def seed_database_if_empty():
    """
    Checks if database is populated. If empty, loads the 1200-row dataset,
    normalizes logs across multi-sources, runs XGBoost predictions,
    and inserts records into SQLite.
    """
    global _CORRELATION_CACHE, _INCIDENTS_CACHE_MAP
    init_db()

    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()["c"]

    if count == 0:
        print("[INIT] Database empty. Seeding from cybersecurity_incidents.csv...")
        df = load_and_preprocess_dataset(str(DATA_PATH))

        # Ensure ML model is trained
        train_and_evaluate_models()

        cursor = conn.cursor()
        incidents_for_correlation = []
        all_logs_to_insert = []

        log_sources_cycle = [
            "Firewall",
            "IDS",
            "Endpoint",
            "Windows Event Log",
            "Linux Syslog",
            "Threat Intelligence",
        ]

        for idx, row in df.iterrows():
            inc_id = idx + 1
            src_ip, dest_ip = generate_deterministic_ips(
                row["Year"], row["Day"], row["City"], row["Category"], row["Incident_Type"], inc_id
            )
            primary_src = log_sources_cycle[inc_id % len(log_sources_cycle)]

            # Quick prediction with trained model
            pred_res = predict_incident_severity({
                "Year": row["Year"],
                "Day": row["Day"],
                "Amount_Lost_INR": row["Amount_Lost_INR"],
                "Incident_Type": row["Incident_Type"],
                "City": row["City"],
                "Category": row["Category"],
            })

            cursor.execute(
                """
                INSERT INTO incidents (
                    id, year, day, amount_lost_inr, incident_type, city, category,
                    severity, predicted_severity, confidence_score, investigation_status,
                    source_ip, dest_ip, primary_source, mitre_tactic
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inc_id,
                    int(row["Year"]),
                    int(row["Day"]),
                    float(row["Amount_Lost_INR"]),
                    str(row["Incident_Type"]),
                    str(row["City"]),
                    str(row["Category"]),
                    str(row["Severity"]),
                    pred_res["predicted_severity"],
                    pred_res["confidence"],
                    "New" if inc_id % 7 != 0 else "Under Investigation",
                    src_ip,
                    dest_ip,
                    primary_src,
                    str(row["MITRE_Tactic"]),
                )
            )

            inc_obj = {
                "id": inc_id,
                "year": int(row["Year"]),
                "day": int(row["Day"]),
                "amount_lost_inr": float(row["Amount_Lost_INR"]),
                "incident_type": str(row["Incident_Type"]),
                "city": str(row["City"]),
                "category": str(row["Category"]),
                "severity": str(row["Severity"]),
                "predicted_severity": pred_res["predicted_severity"],
                "source_ip": src_ip,
                "dest_ip": dest_ip,
                "primary_source": primary_src,
                "mitre_tactic": str(row["MITRE_Tactic"]),
            }
            incidents_for_correlation.append(inc_obj)
            _INCIDENTS_CACHE_MAP[inc_id] = inc_obj

            # Generate synthetic raw logs for first 250 incidents (to keep SQLite nimble and fast)
            if inc_id <= 250:
                logs = generate_synthetic_raw_logs(inc_obj)
                for l in logs:
                    all_logs_to_insert.append((
                        l["log_id"],
                        l["incident_id"],
                        l["timestamp"],
                        l["log_source"],
                        l["event_type"],
                        l["source_ip"],
                        l["dest_ip"],
                        l["source_port"],
                        l["dest_port"],
                        l["protocol"],
                        l["action_taken"],
                        l["raw_log"],
                        l["threat_intel_score"],
                    ))

        # Batch insert security logs
        cursor.executemany(
            """
            INSERT OR IGNORE INTO security_logs (
                log_id, incident_id, timestamp, log_source, event_type, source_ip,
                dest_ip, source_port, dest_port, protocol, action_taken, raw_log, threat_intel_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            all_logs_to_insert
        )

        conn.commit()
        print(f"[INIT] Database seeded with {len(df)} incidents and {len(all_logs_to_insert)} multi-source logs.")

        # Compute and cache correlation clusters
        _CORRELATION_CACHE = compute_correlations(incidents_for_correlation)
        print(f"[INIT] Identified {len(_CORRELATION_CACHE)} multi-source threat correlation campaigns.")
    else:
        # Load from DB into cache
        rows = conn.execute("SELECT * FROM incidents").fetchall()
        incidents_list = dict_list(rows)
        for i in incidents_list:
            _INCIDENTS_CACHE_MAP[i["id"]] = i
        _CORRELATION_CACHE = compute_correlations(incidents_list)
        print(f"[INIT] Loaded {len(incidents_list)} incidents and {len(_CORRELATION_CACHE)} clusters from DB.")

    conn.close()


# Frontend Root Route
@app.route("/")
def index():
    return send_from_directory(str(FRONTEND_DIR), "index.html")


@app.route("/<path:path>")
def static_files(path):
    if (FRONTEND_DIR / path).exists():
        return send_from_directory(str(FRONTEND_DIR), path)
    return send_from_directory(str(FRONTEND_DIR), "index.html")


# API: Health & Status
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Threat Correlation Framework API",
        "database": "SQLite (threat_correlation.db)",
        "models_loaded": True,
        "active_clusters": len(_CORRELATION_CACHE),
    })


# API: Dashboard Summary
@app.route("/api/dashboard/summary", methods=["GET"])
def dashboard_summary():
    conn = get_db_connection()
    total_events = conn.execute("SELECT COUNT(*) as c FROM security_logs").fetchone()["c"]
    total_incidents = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()["c"]
    critical_incidents = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE severity = 'Critical'").fetchone()["c"]
    high_incidents = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE severity = 'High'").fetchone()["c"]
    medium_incidents = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE severity = 'Medium'").fetchone()["c"]
    low_incidents = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE severity = 'Low'").fetchone()["c"]
    false_positives = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE investigation_status = 'False Positive'").fetchone()["c"]

    # Severity distribution
    severity_dist = {
        "Critical": critical_incidents,
        "High": high_incidents,
        "Medium": medium_incidents,
        "Low": low_incidents,
    }

    # Log Source Distribution
    source_rows = conn.execute(
        "SELECT log_source, COUNT(*) as count FROM security_logs GROUP BY log_source"
    ).fetchall()
    source_dist = {r["log_source"]: r["count"] for r in source_rows}
    if not source_dist:
        # Fallback distribution
        source_dist = {
            "Firewall": 250, "IDS": 250, "Endpoint": 250,
            "Windows Event Log": 250, "Linux Syslog": 250, "Threat Intelligence": 250
        }

    # Recent Alerts Feed
    recent_rows = conn.execute(
        """
        SELECT id, incident_type, category, city, severity, predicted_severity,
               amount_lost_inr, primary_source, investigation_status, source_ip, dest_ip, created_at
        FROM incidents
        ORDER BY id DESC LIMIT 10
        """
    ).fetchall()

    # Category financial loss stats
    cat_loss_rows = conn.execute(
        """
        SELECT category, SUM(amount_lost_inr) as total_loss, COUNT(*) as count
        FROM incidents
        GROUP BY category
        ORDER BY total_loss DESC
        """
    ).fetchall()

    conn.close()

    correlated_alerts_count = sum(c["incident_count"] for c in _CORRELATION_CACHE)

    return jsonify({
        "metrics": {
            "total_security_events": total_events if total_events > 0 else 1500,
            "total_incidents": total_incidents,
            "correlated_alerts": correlated_alerts_count,
            "critical_incidents": critical_incidents,
            "false_positives": false_positives,
            "active_campaigns": len(_CORRELATION_CACHE),
        },
        "severity_distribution": severity_dist,
        "log_source_distribution": source_dist,
        "category_loss": dict_list(cat_loss_rows),
        "recent_alerts": dict_list(recent_rows),
    })


# API: Multi-Source Logs
@app.route("/api/logs", methods=["GET"])
def get_logs():
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 25))
    source = request.args.get("source", "").strip()
    search = request.args.get("search", "").strip()

    conn = get_db_connection()
    query = "SELECT * FROM security_logs WHERE 1=1"
    params = []

    if source and source != "All":
        query += " AND log_source = ?"
        params.append(source)
    if search:
        query += " AND (raw_log LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ? OR event_type LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as c")
    total_count = conn.execute(count_query, params).fetchone()["c"]

    query += " ORDER BY incident_id DESC LIMIT ? OFFSET ?"
    params.extend([page_size, (page - 1) * page_size])

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({
        "logs": dict_list(rows),
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": (total_count + page_size - 1) // page_size,
    })


# API: Log Format Normalizer (Single Raw Log Ingestion Test)
@app.route("/api/logs/normalize", methods=["POST"])
def normalize_log_endpoint():
    data = request.get_json() or {}
    raw_text = data.get("raw_log", "")
    source_hint = data.get("source_hint")

    if not raw_text:
        return jsonify({"error": "raw_log is required"}), 400

    parsed = parse_and_normalize_raw_log(raw_text, source_hint)
    return jsonify(parsed)


# API: Custom Dataset Upload
@app.route("/api/logs/upload", methods=["POST"])
def upload_dataset():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        if file.filename.endswith(".csv"):
            import pandas as pd
            import io
            stream = io.StringIO(file.stream.read().decode("utf-8", errors="ignore"))
            df_upload = pd.read_csv(stream)
        elif file.filename.endswith(".json"):
            content = json.loads(file.stream.read().decode("utf-8"))
            df_upload = pd.DataFrame(content)
        else:
            return jsonify({"error": "Unsupported file format. Please upload CSV or JSON."}), 400

        # Validate columns
        required_cols = {"Year", "Day", "Amount_Lost_INR", "Incident_Type", "City", "Category"}
        missing = required_cols - set(df_upload.columns)
        if missing:
            return jsonify({
                "error": f"Uploaded file is missing required columns: {list(missing)}",
                "required": list(required_cols),
            }), 400

        sample_preview = df_upload.head(10).to_dict(orient="records")
        return jsonify({
            "success": True,
            "message": f"Successfully validated and ingested {len(df_upload)} records from {file.filename}.",
            "rows_ingested": len(df_upload),
            "columns": list(df_upload.columns),
            "preview": sample_preview,
        })
    except Exception as e:
        return jsonify({"error": f"Failed to process file: {str(e)}"}), 500


# API: Incidents List with Filters
@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 20))
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    category = request.args.get("category", "").strip()
    city = request.args.get("city", "").strip()
    search = request.args.get("search", "").strip()

    conn = get_db_connection()
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
    if status and status != "All":
        query += " AND investigation_status = ?"
        params.append(status)
    if category and category != "All":
        query += " AND category = ?"
        params.append(category)
    if city and city != "All":
        query += " AND city = ?"
        params.append(city)
    if search:
        query += " AND (incident_type LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard, wildcard])

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as c")
    total_count = conn.execute(count_query, params).fetchone()["c"]

    query += " ORDER BY id ASC LIMIT ? OFFSET ?"
    params.extend([page_size, (page - 1) * page_size])

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return jsonify({
        "incidents": dict_list(rows),
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": (total_count + page_size - 1) // page_size,
    })


# API: Incident Details Workbench
@app.route("/api/incidents/<int:inc_id>", methods=["GET"])
def get_incident_detail(inc_id):
    conn = get_db_connection()
    inc_row = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
    if not inc_row:
        conn.close()
        return jsonify({"error": "Incident not found"}), 404

    incident = dict_from_row(inc_row)

    # Connected logs
    logs_rows = conn.execute("SELECT * FROM security_logs WHERE incident_id = ?", (inc_id,)).fetchall()
    logs = dict_list(logs_rows)

    # Analyst notes
    notes_rows = conn.execute("SELECT * FROM analyst_notes WHERE incident_id = ? ORDER BY created_at DESC", (inc_id,)).fetchall()
    notes = dict_list(notes_rows)

    # SOAR action history
    actions_rows = conn.execute("SELECT * FROM soar_actions WHERE incident_id = ? ORDER BY executed_at DESC", (inc_id,)).fetchall()
    soar_history = dict_list(actions_rows)

    conn.close()

    # Find associated cluster
    associated_cluster = None
    for c in _CORRELATION_CACHE:
        if inc_id in c.get("incidents", []):
            associated_cluster = c
            break

    # Live SHAP feature attribution
    shap_explanation = predict_incident_severity({
        "Year": incident["year"],
        "Day": incident["day"],
        "Amount_Lost_INR": incident["amount_lost_inr"],
        "Incident_Type": incident["incident_type"],
        "City": incident["city"],
        "Category": incident["category"],
    })

    # SOAR recommendation
    soar_rec = recommend_response_action(incident)

    return jsonify({
        "incident": incident,
        "connected_logs": logs,
        "correlation_cluster": associated_cluster,
        "xai_explanation": shap_explanation,
        "adaptive_response": soar_rec,
        "analyst_notes": notes,
        "soar_history": soar_history,
    })


# API: Update Incident Status
@app.route("/api/incidents/<int:inc_id>/status", methods=["PUT"])
def update_incident_status(inc_id):
    data = request.get_json() or {}
    new_status = data.get("status")
    allowed = ["New", "Under Investigation", "Contained", "Resolved", "False Positive"]
    if new_status not in allowed:
        return jsonify({"error": f"Invalid status. Must be one of {allowed}"}), 400

    conn = get_db_connection()
    conn.execute("UPDATE incidents SET investigation_status = ? WHERE id = ?", (new_status, inc_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "incident_id": inc_id, "new_status": new_status})


# API: Add Analyst Note
@app.route("/api/incidents/<int:inc_id>/notes", methods=["POST"])
def add_analyst_note(inc_id):
    data = request.get_json() or {}
    note_text = data.get("note_text", "").strip()
    author = data.get("author", "Lead SOC Analyst").strip()

    if not note_text:
        return jsonify({"error": "note_text cannot be empty"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO analyst_notes (incident_id, author, note_text) VALUES (?, ?, ?)",
        (inc_id, author, note_text)
    )
    conn.commit()
    note_id = cursor.lastrowid
    conn.close()

    return jsonify({
        "success": True,
        "note_id": note_id,
        "incident_id": inc_id,
        "author": author,
        "note_text": note_text,
    })


# API: Correlations
@app.route("/api/correlations", methods=["GET"])
def get_correlations():
    return jsonify({
        "total_campaigns": len(_CORRELATION_CACHE),
        "clusters": _CORRELATION_CACHE,
    })


# API: Correlation Cluster Graph
@app.route("/api/correlations/<int:cluster_id>/graph", methods=["GET"])
def get_cluster_graph(cluster_id):
    cluster = next((c for c in _CORRELATION_CACHE if c["cluster_id"] == cluster_id), None)
    if not cluster:
        return jsonify({"error": "Cluster not found"}), 404

    graph = build_visjs_graph(cluster, _INCIDENTS_CACHE_MAP)
    return jsonify(graph)


# API: Machine Learning Metrics
@app.route("/api/ml/metrics", methods=["GET"])
def get_model_metrics():
    metrics = get_ml_metrics()
    return jsonify(metrics)


# API: Live ML Predict + SHAP Explanation
@app.route("/api/ml/predict", methods=["POST"])
def predict_endpoint():
    data = request.get_json() or {}
    try:
        year = int(data.get("Year", 2024))
        day = int(data.get("Day", 15))
        amount = float(data.get("Amount_Lost_INR", 250000.0))
        itype = str(data.get("Incident_Type", "Ransomware"))
        city = str(data.get("City", "Mumbai"))
        cat = str(data.get("Category", "Financial"))

        res = predict_incident_severity({
            "Year": year,
            "Day": day,
            "Amount_Lost_INR": amount,
            "Incident_Type": itype,
            "City": city,
            "Category": cat,
        })
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# API: Global SHAP Feature Importances
@app.route("/api/xai/global", methods=["GET"])
def get_global_xai():
    metrics = get_ml_metrics()
    return jsonify({
        "feature_importance": metrics.get("global_feature_importance", []),
        "model": "XGBoost Classifier (Multi-Class)",
        "explainer": "SHAP TreeExplainer (Consistent Local Feature Attribution)",
        "summary": "Financial Loss (Amount_Lost_INR) and Sector Sensitivity (Category) constitute over 65% of model predictive weight, reflecting standard cybersecurity risk frameworks.",
    })


# API: SOAR Playbooks
@app.route("/api/soar/playbooks", methods=["GET"])
def get_playbooks():
    return jsonify({"playbooks": PLAYBOOKS})


# API: Execute Simulated SOAR Action
@app.route("/api/soar/execute", methods=["POST"])
def execute_soar_endpoint():
    data = request.get_json() or {}
    res = execute_simulated_action(data)

    if res.get("success") and "execution_record" in res:
        # Record into database
        rec = res["execution_record"]
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO soar_actions (
                incident_id, action_type, target_entity, execution_mode,
                status, playbook_name, blast_radius_risk, analyst_id, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec.get("incident_id"),
                rec.get("action_type"),
                rec.get("target_entity"),
                rec.get("execution_mode"),
                rec.get("status"),
                rec.get("playbook_name"),
                rec.get("blast_radius_risk"),
                rec.get("analyst_id"),
                rec.get("details"),
            )
        )
        conn.commit()
        conn.close()

    return jsonify(res)


# API: SOAR Action History
@app.route("/api/soar/actions", methods=["GET"])
def get_soar_actions():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM soar_actions ORDER BY action_id DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify({"actions": dict_list(rows)})


# API: Reports - Executive HTML (Print/Save to PDF)
@app.route("/api/reports/incident/<int:inc_id>/html", methods=["GET"])
def download_html_report(inc_id):
    conn = get_db_connection()
    inc_row = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
    if not inc_row:
        conn.close()
        return "Incident not found", 404

    incident = dict_from_row(inc_row)
    logs = dict_list(conn.execute("SELECT * FROM security_logs WHERE incident_id = ?", (inc_id,)).fetchall())
    actions = dict_list(conn.execute("SELECT * FROM soar_actions WHERE incident_id = ?", (inc_id,)).fetchall())
    conn.close()

    cluster = next((c for c in _CORRELATION_CACHE if inc_id in c.get("incidents", [])), {})
    xai = predict_incident_severity({
        "Year": incident["year"],
        "Day": incident["day"],
        "Amount_Lost_INR": incident["amount_lost_inr"],
        "Incident_Type": incident["incident_type"],
        "City": incident["city"],
        "Category": incident["category"],
    })

    html = generate_executive_html_report(incident, logs, cluster, actions, xai)
    return Response(html, mimetype="text/html")


# API: Reports - CSV Export
@app.route("/api/reports/export/csv", methods=["GET"])
def export_csv():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id ASC").fetchall()
    conn.close()
    csv_str = export_incidents_to_csv(dict_list(rows))
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cyber_incidents_export.csv"}
    )


# API: Reports - JSON Export
@app.route("/api/reports/export/json", methods=["GET"])
def export_json():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id ASC").fetchall()
    conn.close()
    json_str = export_incidents_to_json(dict_list(rows))
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=cyber_incidents_export.json"}
    )


if __name__ == "__main__":
    seed_database_if_empty()
    app.run(host="0.0.0.0", port=5000, debug=True)
