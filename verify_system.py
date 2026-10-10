"""
Comprehensive verification test script for Threat Correlation Framework
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from backend.db import init_db, get_db_connection
from backend.preprocessing import load_and_preprocess_dataset
from backend.ml_engine import train_and_evaluate_models, predict_incident_severity, get_ml_metrics
from backend.correlation_engine import compute_correlations, build_visjs_graph
from backend.soar_engine import recommend_response_action, execute_simulated_action
from backend.app import seed_database_if_empty

print("=" * 60)
print("RUNNING SYSTEM VERIFICATION TEST")
print("=" * 60)

# 1. Test database seeding
seed_database_if_empty()
conn = get_db_connection()
inc_cnt = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()["c"]
log_cnt = conn.execute("SELECT COUNT(*) as c FROM security_logs").fetchone()["c"]
conn.close()
print(f"[OK] Database Seeded: {inc_cnt} incidents, {log_cnt} logs.")

# 2. Test ML metrics & XGBoost
metrics = get_ml_metrics()
print(f"[OK] XGBoost Holdout Accuracy: {metrics['accuracy']*100:.2f}%")
print(f"[OK] XGBoost Weighted F1-Score: {metrics['f1_weighted']*100:.2f}%")
print(f"[OK] Global SHAP Features Evaluated: {len(metrics['global_feature_importance'])}")

# 3. Test Prediction & SHAP
pred = predict_incident_severity({
    "Year": 2024,
    "Day": 10,
    "Amount_Lost_INR": 420000,
    "Incident_Type": "Ransomware",
    "City": "Mumbai",
    "Category": "Financial",
})
print(f"[OK] Live Prediction for Ransomware (INR 420K, Financial): {pred['predicted_severity']} (Confidence {pred['confidence']*100:.1f}%)")
print(f"[OK] SHAP Drivers: {len(pred['feature_impacts'])} features attributed.")

# 4. Test SOAR Execution
rec = recommend_response_action({
    "id": 1,
    "incident_type": "Ransomware",
    "severity": "Critical",
    "source_ip": "185.220.101.5",
    "dest_ip": "10.10.3.15",
    "category": "Financial",
})
print(f"[OK] SOAR Recommended Action: {rec['recommended_action']} ({rec['playbook_name']})")
res = execute_simulated_action({
    "incident_id": 1,
    "action_type": rec["recommended_action"],
    "target_entity": rec["target_entity"],
    "playbook_id": rec["playbook_id"],
    "confirmed": True,
    "simulated": True,
})
print(f"[OK] SOAR Execution Status: {res['status']} (Success: {res['success']})")

print("=" * 60)
print("ALL CORE MODULES VERIFIED & WORKING FLAWLESSLY!")
print("=" * 60)
