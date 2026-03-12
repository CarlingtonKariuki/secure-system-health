"""
SSHCR Flask Backend
Serves the dashboard and exposes API endpoints that run the actual check modules.

Run with:
    sudo python3 app.py                  # production (port 5000)
    sudo python3 app.py --port 8080      # custom port
    python3 app.py --dev                 # dev mode, no-root warning only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request, send_from_directory

# ── Path setup ────────────────────────────────────────────────────────────────
# Allow running app.py from the repo root with src/ on the path.
BASE_DIR = Path(__file__).parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

from system_checks import run_system_health_checks        # noqa: E402
from network_checks import run_network_checks             # noqa: E402
from security_checks import run_security_checks           # noqa: E402
from report_generator import generate_report              # noqa: E402

# ── App setup ─────────────────────────────────────────────────────────────────
STATIC_DIR = BASE_DIR / "dashboard"          # dashboard HTML lives here
REPORTS_DIR = BASE_DIR / "reports"
HISTORY_FILE = BASE_DIR / "reports" / "history.json"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
REPORTS_DIR.mkdir(exist_ok=True)

# ── In-memory job store ───────────────────────────────────────────────────────
# { job_id: { status, progress, step, result, error } }
_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _count_by_status(results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
    counts = {"OK": 0, "WARNING": 0, "RISK": 0}
    for group in results.values():
        for item in group:
            status = item.get("status", "OK")
            if status in counts:
                counts[status] += 1
    return counts


def _flatten_findings(results: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Return all findings as a flat list with a 'category' field injected."""
    category_map = {
        "system_health": "System",
        "network": "Network",
        "security": "Security",
    }
    flat = []
    for key, group in results.items():
        cat = category_map.get(key, key.title())
        for finding in group:
            f = dict(finding)
            if "category" not in f:
                f["category"] = cat
            flat.append(f)
    return flat


def _load_history() -> List[Dict[str, Any]]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_history(entry: Dict[str, Any]) -> None:
    history = _load_history()
    history.insert(0, entry)
    history = history[:50]          # keep last 50 runs
    HISTORY_FILE.write_text(json.dumps(history, indent=2))


def _run_assessment_thread(
    job_id: str,
    run_health: bool,
    run_network: bool,
    run_security: bool,
) -> None:
    """Background thread: runs checks, updates job store, persists history."""
    def update(status: str, progress: int, step: str) -> None:
        with _jobs_lock:
            _jobs[job_id]["status"] = status
            _jobs[job_id]["progress"] = progress
            _jobs[job_id]["step"] = step

    try:
        results: Dict[str, List[Dict[str, Any]]] = {
            "system_health": [],
            "network": [],
            "security": [],
        }

        update("running", 5, "Initialising assessment environment")

        if run_health:
            update("running", 15, "Running system health checks")
            results["system_health"] = run_system_health_checks()

        if run_network:
            update("running", 40, "Scanning network interfaces & ports")
            results["network"] = run_network_checks()

        if run_security:
            update("running", 65, "Running security baseline evaluation")
            results["security"] = run_security_checks()

        update("running", 85, "Compiling findings & generating report")

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        report_path = generate_report(
            results,
            output_format="html",
            report_name=f"sshcr_report_{date_str}",
        )

        counts = _count_by_status(results)
        findings = _flatten_findings(results)
        total = sum(counts.values())

        # Composite risk score
        composite = 0
        if total > 0:
            composite = round(
                (counts["RISK"] * 85 + counts["WARNING"] * 55 + counts["OK"] * 10) / total
            )

        history_entry = {
            "date": date_str,
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "counts": counts,
            "composite": composite,
            "report_file": str(report_path) if report_path else None,
        }
        _save_history(history_entry)

        payload = {
            "date": date_str,
            "counts": counts,
            "total": total,
            "composite": composite,
            "findings": findings,
            "report_file": str(report_path) if report_path else None,
            "run_at": datetime.now(timezone.utc).isoformat(),
        }

        update("done", 100, "Assessment complete")
        with _jobs_lock:
            _jobs[job_id]["result"] = payload

    except Exception as exc:  # noqa: BLE001
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"] = str(exc)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard HTML."""
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.route("/api/status")
def api_status():
    """Health check — confirms server is running and reports privilege level."""
    return jsonify({
        "ok": True,
        "version": "1.0.0",
        "privileged": os.geteuid() == 0,
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/assess", methods=["POST"])
def api_assess():
    """
    Start an assessment job.

    Body (JSON, all optional):
        { "health": true, "network": true, "security": true }

    Returns:
        { "job_id": "...", "message": "..." }
    """
    body = request.get_json(silent=True) or {}
    full = body.get("full", True)
    run_health   = full or body.get("health", False)
    run_network  = full or body.get("network", False)
    run_security = full or body.get("security", False)

    if not (run_health or run_network or run_security):
        return jsonify({"error": "No checks selected."}), 400

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "queued",
            "progress": 0,
            "step": "Queued",
            "result": None,
            "error": None,
        }

    t = threading.Thread(
        target=_run_assessment_thread,
        args=(job_id, run_health, run_network, run_security),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id, "message": "Assessment started."})


@app.route("/api/assess/<job_id>")
def api_assess_status(job_id: str):
    """
    Poll job status.

    Returns one of:
        { status: "queued"|"running", progress: int, step: str }
        { status: "done",   progress: 100, result: {...} }
        { status: "error",  error: "..." }
    """
    with _jobs_lock:
        job = _jobs.get(job_id)

    if job is None:
        return jsonify({"error": "Unknown job ID."}), 404

    response: Dict[str, Any] = {
        "status":   job["status"],
        "progress": job["progress"],
        "step":     job["step"],
    }

    if job["status"] == "done":
        response["result"] = job["result"]
        # Clean up job from memory after delivery
        with _jobs_lock:
            _jobs.pop(job_id, None)

    elif job["status"] == "error":
        response["error"] = job["error"]
        with _jobs_lock:
            _jobs.pop(job_id, None)

    return jsonify(response)


@app.route("/api/history")
def api_history():
    """Return the last 50 assessment runs."""
    return jsonify(_load_history())


@app.route("/api/reports")
def api_reports():
    """List available report files in the reports/ directory."""
    files = []
    for f in sorted(REPORTS_DIR.glob("sshcr_report_*.html"), reverse=True):
        files.append({
            "filename": f.name,
            "size_kb": round(f.stat().st_size / 1024, 1),
            "modified": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
        })
    return jsonify(files)


@app.route("/api/reports/<filename>")
def api_download_report(filename: str):
    """Download a specific report file."""
    safe = Path(filename).name          # strip any path traversal
    return send_from_directory(str(REPORTS_DIR), safe)


# ── Dev / prod entry point ────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SSHCR Flask dashboard server")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--dev", action="store_true", help="Enable Flask debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if os.geteuid() != 0:
        print(
            "[WARNING] Running without root. Some checks will be incomplete.\n"
            "          Re-run with: sudo python3 app.py\n",
            file=sys.stderr,
        )

    print(f"[*] SSHCR dashboard starting on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.dev, threaded=True)
