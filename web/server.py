#!/usr/bin/env python3
"""
APK QA Web Server
Serves a web UI and runs the apk_qa_agent.py script via subprocess.
Usage: ANTHROPIC_API_KEY=sk-... python3 web/server.py
"""

import json
import os
import select
import subprocess
import sys
import tempfile
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 250 * 1024 * 1024  # 250 MB upload limit

REPO_ROOT = Path(__file__).parent.parent
AGENT_SCRIPT = REPO_ROOT / "apk_qa_agent.py"
UPLOAD_DIR = Path(tempfile.gettempdir()) / "apk_qa_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Accepts:
    - multipart form with 'apk_file' field (file upload)
    - form field 'apk_path' (server-side file path)

    Streams Server-Sent Events with progress and final verdict.
    """
    apk_path = None
    temp_file = None

    if "apk_file" in request.files:
        f = request.files["apk_file"]
        if not f.filename or not f.filename.lower().endswith(".apk"):
            return jsonify({"error": "Invalid file: must be an .apk file"}), 400
        fd, temp_path = tempfile.mkstemp(suffix=".apk", dir=str(UPLOAD_DIR))
        os.close(fd)
        f.save(temp_path)
        apk_path = temp_path
        temp_file = temp_path

    elif "apk_path" in request.form:
        apk_path = request.form["apk_path"].strip()
        if not os.path.isfile(apk_path):
            return jsonify({"error": f"File not found: {apk_path}"}), 400
    else:
        return jsonify({"error": "No APK provided"}), 400

    def generate():
        try:
            env = os.environ.copy()
            proc = subprocess.Popen(
                [sys.executable, str(AGENT_SCRIPT), apk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                bufsize=1,
            )

            stdout_data = []
            stderr_data = []

            # Non-blocking reads from both pipes using select
            while True:
                rlist = []
                if not proc.stdout.closed:
                    rlist.append(proc.stdout.fileno())
                if not proc.stderr.closed:
                    rlist.append(proc.stderr.fileno())

                readable, _, _ = select.select(rlist, [], [], 0.2)

                for fd in readable:
                    if fd == proc.stderr.fileno():
                        line = proc.stderr.readline()
                        if line:
                            msg = line.rstrip()
                            stderr_data.append(msg)
                            yield f"data: {json.dumps({'type': 'progress', 'msg': msg})}\n\n"
                    elif fd == proc.stdout.fileno():
                        line = proc.stdout.readline()
                        if line:
                            stdout_data.append(line.rstrip())

                if proc.poll() is not None:
                    # Drain remaining output
                    for line in proc.stderr:
                        msg = line.rstrip()
                        stderr_data.append(msg)
                        yield f"data: {json.dumps({'type': 'progress', 'msg': msg})}\n\n"
                    for line in proc.stdout:
                        stdout_data.append(line.rstrip())
                    break

            # Find the JSON verdict (entire stdout is JSON from the agent)
            verdict = None
            stdout_text = "\n".join(stdout_data).strip()
            if stdout_text:
                try:
                    verdict = json.loads(stdout_text)
                except json.JSONDecodeError:
                    # Try to find the first valid JSON object in the output
                    import re
                    m = re.search(r"\{[\s\S]+\}", stdout_text)
                    if m:
                        try:
                            verdict = json.loads(m.group(0))
                        except json.JSONDecodeError:
                            pass

            if verdict and "error" not in verdict:
                yield f"data: {json.dumps({'type': 'complete', 'verdict': verdict})}\n\n"
            else:
                error_detail = ""
                if verdict and "error" in verdict:
                    error_detail = verdict["error"]
                else:
                    error_detail = "\n".join(stderr_data[-15:]) if stderr_data else "No output from agent"
                yield f"data: {json.dumps({'type': 'error', 'msg': error_detail})}\n\n"

        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'msg': str(exc)})}\n\n"
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[WARNING] ANTHROPIC_API_KEY is not set. AI analysis will fail.", file=sys.stderr)
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting APK QA Web UI on http://0.0.0.0:{port}", file=sys.stderr)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
