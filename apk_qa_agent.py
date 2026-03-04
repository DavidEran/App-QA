#!/usr/bin/env python3
"""
APK QA Automation Agent
Analyzes Android APK files and produces structured QA reports.
Usage: ANTHROPIC_API_KEY=sk-... python3 apk_qa_agent.py /path/to/app.apk
"""

import json
import os
import re
import subprocess
import sys
import tempfile

DECOMPILE_DIR = "/tmp/apk_decompiled"
RAW_DIR = "/tmp/apk_raw"
POLICY_TEXT_LIMIT = 8000


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def run_cmd(args, timeout=120, input_data=None):
    """Run a shell command and return stdout as a string. Returns '' on error."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        return result.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def grep_dir(pattern, directory, extra_flags=None, include="", max_lines=40):
    """Run grep recursively in a directory. Returns list of matching lines."""
    if not os.path.isdir(directory):
        return []
    cmd = ["grep", "-r", "--text"]
    if extra_flags:
        cmd.extend(extra_flags)
    if include:
        cmd.extend(["--include", include])
    cmd.extend([pattern, directory])
    output = run_cmd(cmd, timeout=60)
    lines = [ln for ln in output.splitlines() if ln.strip()]
    return lines[:max_lines]


def grep_file(pattern, filepath, extra_flags=None):
    """Run grep on a single file. Returns list of matching lines."""
    if not os.path.isfile(filepath):
        return []
    cmd = ["grep", "--text"]
    if extra_flags:
        cmd.extend(extra_flags)
    cmd.extend([pattern, filepath])
    output = run_cmd(cmd, timeout=30)
    return [l for l in output.splitlines() if l.strip()]


# ---------------------------------------------------------------------------
# CHECK 1 — APK Size
# ---------------------------------------------------------------------------

def check_apk_size(apk_path):
    size_bytes = os.path.getsize(apk_path)
    size_mb = round(size_bytes / (1024 * 1024), 2)
    return {"size_bytes": size_bytes, "size_mb": size_mb}


# ---------------------------------------------------------------------------
# CHECK 2 — Decompile APK
# ---------------------------------------------------------------------------

def check_decompile(apk_path):
    """Decompile with apktool and also extract raw zip contents."""
    # apktool decompile
    run_cmd(["apktool", "d", apk_path, "-o", DECOMPILE_DIR, "-f"], timeout=180)

    # Raw zip extraction
    os.makedirs(RAW_DIR, exist_ok=True)
    extracted_dir = os.path.join(RAW_DIR, "extracted")
    os.makedirs(extracted_dir, exist_ok=True)
    zip_path = os.path.join(RAW_DIR, "app.zip")
    try:
        import shutil
        shutil.copy2(apk_path, zip_path)
        run_cmd(["unzip", "-o", zip_path, "-d", extracted_dir], timeout=120)
    except Exception:
        pass

    smali_dir = os.path.join(DECOMPILE_DIR, "smali")
    res_dir = os.path.join(DECOMPILE_DIR, "res")
    manifest_path = os.path.join(DECOMPILE_DIR, "AndroidManifest.xml")

    return {
        "smali_dir": smali_dir if os.path.isdir(smali_dir) else None,
        "res_dir": res_dir if os.path.isdir(res_dir) else None,
        "manifest_path": manifest_path if os.path.isfile(manifest_path) else None,
        "decompile_dir": DECOMPILE_DIR,
        "extracted_dir": extracted_dir,
    }


# ---------------------------------------------------------------------------
# CHECK 3 — Permissions & Wake Lock
# ---------------------------------------------------------------------------

def check_permissions_wakelock(apk_path, decompile):
    result = {}

    # Parse permissions via aapt
    aapt_output = run_cmd(["aapt", "dump", "permissions", apk_path], timeout=30)
    permissions = []
    for line in aapt_output.splitlines():
        m = re.search(r"name='([^']+)'", line)
        if m:
            permissions.append(m.group(1))

    # Fallback: grep manifest
    if not permissions and decompile.get("manifest_path"):
        manifest_lines = grep_file("permission", decompile["manifest_path"], ["-i"])
        for line in manifest_lines:
            m = re.search(r'android:name="([^"]+)"', line)
            if m and "permission" in m.group(1).lower():
                permissions.append(m.group(1))

    result["permissions"] = list(set(permissions))

    # Wake lock code search in smali (use decompile_dir to cover multi-dex APKs)
    wakelock_hits = []
    smali_search_root = decompile.get("decompile_dir") or decompile.get("smali_dir")
    if smali_search_root:
        wakelock_hits = grep_dir(
            r"WAKE_LOCK\|acquire\|wakelock",
            smali_search_root,
            extra_flags=["-E", "-i"],
            include="*.smali",
        )

    # Wake lock in XML resources
    wakelock_xml_hits = []
    if decompile.get("decompile_dir"):
        wakelock_xml_hits = grep_dir(
            r"wakelock\|WakeLock\|wake_lock",
            decompile["decompile_dir"],
            extra_flags=["-E", "-i"],
            include="*.xml",
        )

    result["wakelock_code_hits"] = wakelock_hits
    result["wakelock_xml_hits"] = wakelock_xml_hits

    return result


# ---------------------------------------------------------------------------
# CHECK 4 — Play Integrity Detection
# ---------------------------------------------------------------------------

def check_play_integrity(decompile):
    result = {}

    # Use decompile_dir as root to cover multi-dex APKs (smali/, smali_classes2/, etc.)
    decompile_dir = decompile.get("decompile_dir")

    # Integrity API hits
    integrity_hits = []
    if decompile_dir:
        integrity_hits = grep_dir(
            r"IntegrityManager\|StandardIntegrityManager\|requestIntegrityToken\|IntegrityTokenRequest\|INTEGRITY\|integrity",
            decompile_dir,
            extra_flags=["-E"],
            include="*.smali",
        )
    result["play_integrity_hits"] = integrity_hits

    # Firebase AppCheck
    appcheck_hits = []
    if decompile_dir:
        appcheck_hits = grep_dir(
            r"AppCheck\|appcheck\|app_check\|FirebaseAppCheck",
            decompile_dir,
            extra_flags=["-E", "-i"],
            include="*.smali",
        )
    result["firebase_appcheck_hits"] = appcheck_hits

    # pairip auto-protection
    pairip_hits = []
    if decompile_dir:
        pairip_hits = grep_dir(
            r"pairip\|PairipCore\|com/google/android/play/integrity",
            decompile_dir,
            extra_flags=["-E", "-i"],
            include="*.smali",
        )
    result["pairip_hits"] = pairip_hits

    # Licensing verdict strings
    licensing_hits = []
    if decompile_dir:
        licensing_hits = grep_dir(
            r"GET_LICENSED\|appLicensingVerdict\|LICENSED\|UNLICENSED",
            decompile_dir,
            extra_flags=["-E"],
            include="*.smali",
        )
    result["licensing_hits"] = licensing_hits

    # XML: play.core / gms.tasks
    xml_hits = []
    if decompile_dir:
        xml_hits = grep_dir(
            r"com\.google\.android\.play\.core\|com\.google\.android\.gms\.tasks",
            decompile_dir,
            extra_flags=["-E"],
            include="*.xml",
        )
    result["play_xml_hits"] = xml_hits

    return result


# ---------------------------------------------------------------------------
# CHECK 5 — Privacy Policy & Terms Detection
# ---------------------------------------------------------------------------

def check_privacy_policy(decompile):
    result = {}

    res_dir = decompile.get("res_dir")
    smali_dir = decompile.get("smali_dir")
    manifest_path = decompile.get("manifest_path")

    # Strings with privacy/terms keywords in XML resources
    privacy_strings = []
    if res_dir:
        privacy_strings = grep_dir(
            r"privacy\|terms\|policy\|legal\|tos\|eula\|gdpr\|agreement",
            res_dir,
            extra_flags=["-E", "-i"],
            include="*.xml",
        )
    result["privacy_strings"] = privacy_strings

    # URLs containing privacy/terms keywords — in res
    privacy_urls = []
    if res_dir:
        url_output = run_cmd(
            ["grep", "-roh", r"https\?://[^\"'< ]*", res_dir],
            timeout=30,
        )
        for url in url_output.splitlines():
            if re.search(r"privacy|terms|policy|legal|tos|eula", url, re.IGNORECASE):
                privacy_urls.append(url.strip())
    # URLs in smali (search full decompile_dir for multi-dex coverage)
    smali_search = decompile.get("decompile_dir") or decompile.get("smali_dir")
    if smali_search:
        url_output = run_cmd(
            ["grep", "-roh", "--include=*.smali", r"https\?://[^\"'< ]*", smali_search],
            timeout=30,
        )
        for url in url_output.splitlines():
            if re.search(r"privacy|terms|policy|legal|tos|eula", url, re.IGNORECASE):
                privacy_urls.append(url.strip())

    result["privacy_urls"] = list(set(privacy_urls))

    # Terms-specific strings
    terms_strings = []
    if res_dir:
        terms_strings = grep_dir(
            r"terms\|conditions\|eula\|agreement",
            res_dir,
            extra_flags=["-E", "-i"],
            include="*.xml",
            max_lines=20,
        )
    result["terms_strings"] = terms_strings

    # Manifest: activities with privacy/terms names
    manifest_hits = []
    if manifest_path:
        manifest_hits = grep_file(
            r"privacy\|terms\|policy\|legal\|consent\|eula",
            manifest_path,
            extra_flags=["-E", "-i"],
        )
    result["manifest_hits"] = manifest_hits

    return result


# ---------------------------------------------------------------------------
# CHECK 6 — Fetch Privacy Policy Content
# ---------------------------------------------------------------------------

def fetch_policy_text(url):
    """Fetch a URL and strip HTML tags, returning plain text up to POLICY_TEXT_LIMIT chars."""
    if not url:
        return ""
    try:
        output = run_cmd(
            ["curl", "-s", "--max-time", "15", "-L", url],
            timeout=20,
        )
        # Strip HTML tags
        text = re.sub(r"<[^>]+>", " ", output)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:POLICY_TEXT_LIMIT]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# AI ANALYSIS — Claude API
# ---------------------------------------------------------------------------

VERDICT_PROMPT_TEMPLATE = """You are an Android APK QA analyst. Analyze the following raw findings from an APK and produce a structured QA verdict.

RAW FINDINGS:
{findings_json}

Produce a JSON response with EXACTLY this structure:
{{
  "apk_size": {{
    "verdict": "PASS" | "FLAG",
    "size_mb": <number>,
    "note": "<brief explanation>"
  }},
  "privacy_policy": {{
    "verdict": "FOUND" | "NOT FOUND" | "LIKELY FOUND",
    "url": "<url or null>",
    "accessible_in_app": true | false | "unknown",
    "note": "<explanation of where/how it's accessible>"
  }},
  "terms_and_conditions": {{
    "verdict": "FOUND" | "NOT FOUND" | "LIKELY FOUND",
    "url": "<url or null>",
    "accessible_in_app": true | false | "unknown",
    "note": "<explanation>"
  }},
  "data_collected": {{
    "verdict": "DATA IDENTIFIED" | "NO POLICY TO ANALYZE" | "POLICY FOUND BUT VAGUE",
    "categories": [
      "<data category 1>",
      "<data category 2>"
    ],
    "note": "<summary of what personal data is collected according to the privacy policy>"
  }},
  "wake_lock": {{
    "verdict": "DETECTED" | "NOT DETECTED" | "PERMISSION ONLY",
    "permission_declared": true | false,
    "active_usage_found": true | false,
    "lock_types": ["<type1>", "<type2>"],
    "timeout_ms": <number or null>,
    "note": "<explanation of usage pattern>"
  }},
  "play_integrity": {{
    "verdict": "DETECTED - RISK" | "DETECTED - LOW RISK" | "NOT DETECTED",
    "uses_integrity_api": true | false,
    "uses_auto_protection_pairip": true | false,
    "uses_firebase_appcheck": true | false,
    "handles_unlicensed_gracefully": true | false | "unknown",
    "forces_play_store_redirect": true | false | "unknown",
    "note": "<explanation of risk for sideloaded/DT installs — does this app risk blocking users who install via Digital Turbine or similar third-party installers?>"
  }},
  "overall_risk": "LOW" | "MEDIUM" | "HIGH",
  "summary": "<2-3 sentence executive summary of QA findings>"
}}

Be precise. Base verdicts ONLY on the evidence in the raw findings. If something is not found in the code, say NOT DETECTED rather than guessing.
Return ONLY the JSON object, no markdown fences or other text."""


def call_claude_api(findings):
    """Call Anthropic API with the findings dict. Returns parsed JSON verdict."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable not set")

    prompt = VERDICT_PROMPT_TEMPLATE.format(
        findings_json=json.dumps(findings, indent=2)
    )

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    payload = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": prompt}],
    }

    import requests as req_lib
    resp = req_lib.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json=payload,
        timeout=90,
    )
    resp.raise_for_status()
    content = resp.json()["content"][0]["text"].strip()

    # Strip markdown fences if present
    content = re.sub(r"^```[a-z]*\n?", "", content)
    content = re.sub(r"\n?```$", "", content)

    return json.loads(content)


# ---------------------------------------------------------------------------
# REPORT FORMATTER
# ---------------------------------------------------------------------------

def _verdict_icon(v):
    v = str(v).upper()
    if any(x in v for x in ("PASS", "NOT DETECTED", "LOW", "FOUND")):
        return "✅"
    if any(x in v for x in ("FLAG", "MEDIUM", "LIKELY")):
        return "⚠️"
    if any(x in v for x in ("RISK", "HIGH", "NOT FOUND")):
        return "❌"
    return "ℹ️"


def format_report(verdict):
    lines = []
    lines.append("=" * 60)
    lines.append("  APK QA REPORT")
    lines.append("=" * 60)

    # APK Size
    s = verdict.get("apk_size", {})
    icon = _verdict_icon(s.get("verdict", ""))
    lines.append(f"\n{icon} APK SIZE: {s.get('verdict', 'N/A')} ({s.get('size_mb', '?')} MB)")
    lines.append(f"   {s.get('note', '')}")

    # Privacy Policy
    p = verdict.get("privacy_policy", {})
    icon = _verdict_icon(p.get("verdict", ""))
    lines.append(f"\n{icon} PRIVACY POLICY: {p.get('verdict', 'N/A')}")
    if p.get("url"):
        lines.append(f"   URL: {p['url']}")
    lines.append(f"   Accessible in-app: {p.get('accessible_in_app', 'unknown')}")
    lines.append(f"   {p.get('note', '')}")

    # Terms & Conditions
    t = verdict.get("terms_and_conditions", {})
    icon = _verdict_icon(t.get("verdict", ""))
    lines.append(f"\n{icon} TERMS & CONDITIONS: {t.get('verdict', 'N/A')}")
    if t.get("url"):
        lines.append(f"   URL: {t['url']}")
    lines.append(f"   Accessible in-app: {t.get('accessible_in_app', 'unknown')}")
    lines.append(f"   {t.get('note', '')}")

    # Data Collected
    d = verdict.get("data_collected", {})
    icon = _verdict_icon(d.get("verdict", ""))
    lines.append(f"\n{icon} DATA COLLECTED: {d.get('verdict', 'N/A')}")
    cats = d.get("categories", [])
    if cats:
        lines.append(f"   Categories: {', '.join(cats)}")
    lines.append(f"   {d.get('note', '')}")

    # Wake Lock
    w = verdict.get("wake_lock", {})
    icon = _verdict_icon(w.get("verdict", ""))
    lines.append(f"\n{icon} WAKE LOCK: {w.get('verdict', 'N/A')}")
    lines.append(f"   Permission declared: {w.get('permission_declared', False)}")
    lines.append(f"   Active usage found: {w.get('active_usage_found', False)}")
    lock_types = w.get("lock_types", [])
    if lock_types:
        lines.append(f"   Lock types: {', '.join(lock_types)}")
    if w.get("timeout_ms") is not None:
        lines.append(f"   Timeout: {w['timeout_ms']} ms")
    lines.append(f"   {w.get('note', '')}")

    # Play Integrity
    pi = verdict.get("play_integrity", {})
    icon = _verdict_icon(pi.get("verdict", ""))
    lines.append(f"\n{icon} PLAY INTEGRITY: {pi.get('verdict', 'N/A')}")
    lines.append(f"   Uses Integrity API: {pi.get('uses_integrity_api', False)}")
    lines.append(f"   Uses pairip auto-protection: {pi.get('uses_auto_protection_pairip', False)}")
    lines.append(f"   Uses Firebase AppCheck: {pi.get('uses_firebase_appcheck', False)}")
    lines.append(f"   Forces Play Store redirect: {pi.get('forces_play_store_redirect', 'unknown')}")
    lines.append(f"   {pi.get('note', '')}")

    # Overall Risk
    risk = verdict.get("overall_risk", "UNKNOWN")
    icon = _verdict_icon(risk)
    lines.append(f"\n{icon} OVERALL RISK: {risk}")

    # Summary
    lines.append(f"\n📋 SUMMARY:")
    lines.append(f"   {verdict.get('summary', '')}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main(apk_path):
    if not os.path.isfile(apk_path):
        print(json.dumps({"error": f"APK file not found: {apk_path}"}))
        sys.exit(1)

    print(f"[*] Analyzing APK: {apk_path}", file=sys.stderr)

    # CHECK 1
    print("[1/6] Checking APK size...", file=sys.stderr)
    size_info = check_apk_size(apk_path)

    # CHECK 2
    print("[2/6] Decompiling APK...", file=sys.stderr)
    decompile = check_decompile(apk_path)

    # CHECK 3
    print("[3/6] Checking permissions and wake lock...", file=sys.stderr)
    perm_info = check_permissions_wakelock(apk_path, decompile)

    # CHECK 4
    print("[4/6] Checking Play Integrity API usage...", file=sys.stderr)
    integrity_info = check_play_integrity(decompile)

    # CHECK 5
    print("[5/6] Detecting privacy policy & terms...", file=sys.stderr)
    privacy_info = check_privacy_policy(decompile)

    # CHECK 6
    print("[6/6] Fetching privacy policy content...", file=sys.stderr)
    privacy_urls = privacy_info.get("privacy_urls", [])
    policy_text = ""
    if privacy_urls:
        policy_text = fetch_policy_text(privacy_urls[0])

    # Assemble findings
    findings = {
        "apk_path": apk_path,
        "apk_size_bytes": size_info["size_bytes"],
        "apk_size_mb": size_info["size_mb"],
        "permissions": perm_info.get("permissions", []),
        "wakelock_code_hits": perm_info.get("wakelock_code_hits", []),
        "wakelock_xml_hits": perm_info.get("wakelock_xml_hits", []),
        "play_integrity_hits": integrity_info.get("play_integrity_hits", []),
        "firebase_appcheck_hits": integrity_info.get("firebase_appcheck_hits", []),
        "pairip_hits": integrity_info.get("pairip_hits", []),
        "licensing_hits": integrity_info.get("licensing_hits", []),
        "play_xml_hits": integrity_info.get("play_xml_hits", []),
        "privacy_strings": privacy_info.get("privacy_strings", []),
        "privacy_urls": privacy_info.get("privacy_urls", []),
        "terms_strings": privacy_info.get("terms_strings", []),
        "manifest_hits": privacy_info.get("manifest_hits", []),
        "privacy_policy_text": policy_text,
    }

    # AI Analysis
    print("[AI] Calling Claude API for analysis...", file=sys.stderr)
    verdict = call_claude_api(findings)

    # Output JSON verdict (machine-readable)
    print(json.dumps(verdict, indent=2))

    # Output formatted report (human-readable)
    print("\n" + format_report(verdict), file=sys.stderr)

    return verdict


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apk_qa_agent.py <path_to_apk>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
