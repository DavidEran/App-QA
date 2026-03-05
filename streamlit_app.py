"""
APK QA Analyzer — Streamlit App
Run: streamlit run streamlit_app.py
"""

import json
import os
import sys
import tempfile

import streamlit as st

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="APK QA Analyzer",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Import agent (same repo) ──────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
import apk_qa_agent as qa

# ── Helpers ───────────────────────────────────────────────────────────────────

def verdict_color(v: str) -> str:
    v = str(v).upper()
    if any(x in v for x in ("PASS", "NOT DETECTED", "NOT FOUND")):
        return "normal"          # neutral/grey for NOT FOUND (no risk)
    if any(x in v for x in ("FOUND", "LOW")):
        return "normal"
    if any(x in v for x in ("FLAG", "MEDIUM", "LIKELY", "PERMISSION ONLY", "LOW RISK")):
        return "off"
    if any(x in v for x in ("RISK", "HIGH", "DETECTED")):
        return "inverse"
    return "normal"


def risk_emoji(v: str) -> str:
    v = str(v).upper()
    if any(x in v for x in ("PASS", "NOT DETECTED", "LOW")):
        return "✅"
    if any(x in v for x in ("FLAG", "MEDIUM", "LIKELY", "PERMISSION", "LOW RISK")):
        return "⚠️"
    if any(x in v for x in ("RISK", "HIGH", "DETECTED", "NOT FOUND")):
        return "❌"
    return "ℹ️"


def render_verdict_badge(v: str) -> str:
    """Return coloured markdown text for a verdict string."""
    v = str(v)
    upper = v.upper()
    if any(x in upper for x in ("PASS", "NOT DETECTED", "LOW", "FOUND")):
        return f":green[**{v}**]"
    if any(x in upper for x in ("FLAG", "MEDIUM", "LIKELY", "PERMISSION ONLY", "LOW RISK")):
        return f":orange[**{v}**]"
    return f":red[**{v}**]"


def render_raw_findings(findings: dict):
    """Display raw findings when AI analysis is skipped."""
    sz = findings.get("apk_size_mb", "?")
    st.markdown(f"### 📦 APK Size: **{sz} MB** {'🚩 Large APK' if sz and sz > 100 else ''}")

    perms = findings.get("permissions", [])
    st.markdown(f"### 🔍 Permissions ({len(perms)})")
    if perms:
        st.code("\n".join(sorted(perms)))
    else:
        st.caption("None found (aapt may not be installed)")

    col1, col2 = st.columns(2)

    with col1:
        wl = findings.get("wakelock_code_hits", [])
        st.markdown(f"### 🔋 Wake Lock hits ({len(wl)})")
        if wl:
            st.code("\n".join(wl[:15]))
        else:
            st.caption("No wake lock code found")

        pi = findings.get("play_integrity_hits", [])
        pairip = findings.get("pairip_hits", [])
        ac = findings.get("firebase_appcheck_hits", [])
        st.markdown(f"### 🛡️ Play Integrity hits ({len(pi)}) · pairip ({len(pairip)}) · AppCheck ({len(ac)})")
        for label, hits in [("Integrity API", pi), ("pairip", pairip), ("Firebase AppCheck", ac)]:
            if hits:
                with st.expander(f"{label} ({len(hits)} hits)"):
                    st.code("\n".join(hits[:10]))

    with col2:
        urls = findings.get("privacy_urls", [])
        st.markdown(f"### 🔏 Privacy / Terms URLs ({len(urls)})")
        if urls:
            for u in urls:
                st.markdown(f"- [{u}]({u})")
        else:
            st.caption("No policy URLs detected")

        ps = findings.get("privacy_strings", [])
        st.markdown(f"### 📄 Privacy strings in resources ({len(ps)})")
        if ps:
            with st.expander("Show strings"):
                st.code("\n".join(ps[:20]))

    with st.expander("Full raw findings JSON"):
        st.json(findings)


def run_analysis(apk_path: str, skip_ai: bool = False) -> dict:
    """Run all checks. If skip_ai=True, return raw findings without calling Claude API."""
    with st.status("Analyzing APK…", expanded=True) as status:
        st.write("📦 **Step 1/6** — Checking APK size…")
        size_info = qa.check_apk_size(apk_path)
        sz = size_info["size_mb"]
        st.write(f"   → {sz} MB {'🚩 Large APK' if sz > 100 else '✅ OK'}")

        st.write("⚙️ **Step 2/6** — Decompiling APK with apktool…")
        decompile = qa.check_decompile(apk_path)
        if decompile.get("smali_dir") or decompile.get("decompile_dir"):
            st.write("   → Decompile complete")
        else:
            st.write("   → ⚠️ Decompile produced no smali dir (apktool may not be installed)")

        st.write("🔍 **Step 3/6** — Permissions & Wake Lock…")
        perm_info = qa.check_permissions_wakelock(apk_path, decompile)
        n_perms = len(perm_info.get("permissions", []))
        n_wl = len(perm_info.get("wakelock_code_hits", []))
        st.write(f"   → {n_perms} permissions found, {n_wl} wake-lock code hits")

        st.write("🛡️ **Step 4/6** — Play Integrity API detection…")
        integrity_info = qa.check_play_integrity(decompile)
        n_pi = len(integrity_info.get("play_integrity_hits", []))
        st.write(f"   → {n_pi} integrity-related code hits")

        st.write("🔏 **Step 5/6** — Privacy policy & terms detection…")
        privacy_info = qa.check_privacy_policy(decompile)
        urls = privacy_info.get("privacy_urls", [])
        st.write(f"   → {len(urls)} policy URL(s) found")

        policy_text = ""
        if urls:
            st.write(f"📥 **Step 6/6** — Fetching policy content from {urls[0][:60]}…")
            policy_text = qa.fetch_policy_text(urls[0])
            st.write(f"   → {len(policy_text)} characters fetched")
        else:
            st.write("📥 **Step 6/6** — No policy URL to fetch")

        findings = qa.assemble_findings(
            apk_path, size_info, perm_info, integrity_info, privacy_info, policy_text
        )

        if skip_ai:
            status.update(label="✅ Raw scan complete (no AI analysis)", state="complete", expanded=False)
            return {"__raw__": True, "findings": findings}

        st.write("🤖 **Calling Claude API** for structured analysis…")
        verdict = qa.call_claude_api(findings)
        status.update(label="✅ Analysis complete!", state="complete", expanded=False)

    return verdict


def render_results(verdict: dict):
    # ── Overall risk banner ───────────────────────────────────────────────────
    risk = verdict.get("overall_risk", "UNKNOWN")
    risk_colors = {"LOW": "🟢", "MEDIUM": "🟠", "HIGH": "🔴"}
    icon = risk_colors.get(risk.upper(), "⬜")
    st.markdown(f"## {icon} Overall Risk: {render_verdict_badge(risk)}")

    summary = verdict.get("summary", "")
    if summary:
        st.info(summary)

    st.divider()

    # ── Check cards in 3-column grid ─────────────────────────────────────────
    checks = [
        ("apk_size",             "APK Size",           "📦"),
        ("privacy_policy",       "Privacy Policy",     "🔏"),
        ("terms_and_conditions", "Terms & Conditions", "📄"),
        ("data_collected",       "Data Collection",    "📊"),
        ("wake_lock",            "Wake Lock",          "🔋"),
        ("play_integrity",       "Play Integrity",     "🛡️"),
    ]

    cols = st.columns(3)
    for i, (key, label, icon) in enumerate(checks):
        data = verdict.get(key, {})
        v = data.get("verdict", "N/A")
        note = data.get("note", "")
        col = cols[i % 3]

        with col:
            st.markdown(f"### {icon} {label}")
            st.markdown(f"{risk_emoji(v)} {render_verdict_badge(v)}")
            st.caption(note)

            # Key sub-fields
            if key == "apk_size":
                st.caption(f"Size: **{data.get('size_mb', '?')} MB**")

            elif key in ("privacy_policy", "terms_and_conditions"):
                url = data.get("url")
                if url:
                    st.markdown(f"[View Policy]({url})")
                st.caption(f"Accessible in-app: **{data.get('accessible_in_app', 'unknown')}**")

            elif key == "data_collected":
                cats = data.get("categories", [])
                if cats:
                    st.caption("Categories: " + ", ".join(cats))

            elif key == "wake_lock":
                st.caption(
                    f"Permission declared: **{data.get('permission_declared', False)}** | "
                    f"Active usage: **{data.get('active_usage_found', False)}**"
                )
                lock_types = data.get("lock_types", [])
                if lock_types:
                    st.caption("Types: " + ", ".join(lock_types))

            elif key == "play_integrity":
                st.caption(
                    f"Integrity API: **{data.get('uses_integrity_api', False)}** | "
                    f"pairip: **{data.get('uses_auto_protection_pairip', False)}** | "
                    f"AppCheck: **{data.get('uses_firebase_appcheck', False)}**"
                )

            with st.expander("Raw JSON"):
                st.json(data)

    st.divider()

    # ── Full verdict JSON ─────────────────────────────────────────────────────
    with st.expander("Full verdict JSON"):
        st.json(verdict)


# ── Main App ──────────────────────────────────────────────────────────────────

def main():
    st.title("🤖 APK QA Analyzer")
    st.caption("Automated Android APK quality assurance — powered by Claude AI")

    # ── API key resolution ────────────────────────────────────────────────────
    api_key = st.secrets.get("ANTHROPIC_API_KEY", "") if hasattr(st, "secrets") else ""
    if not api_key:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        os.environ["ANTHROPIC_API_KEY"] = api_key
    else:
        st.warning(
            "⚠️ `ANTHROPIC_API_KEY` not set — AI analysis is disabled. "
            "You can still run a **raw scan** (checks 1–5) without it. "
            "To enable AI verdicts, add the key to `.streamlit/secrets.toml` or set it as an environment variable.",
            icon="🔑",
        )

    # ── Session state ─────────────────────────────────────────────────────────
    if "verdict" not in st.session_state:
        st.session_state.verdict = None
    if "apk_name" not in st.session_state:
        st.session_state.apk_name = None

    # ── Input section ─────────────────────────────────────────────────────────
    if st.session_state.verdict is None:
        st.subheader("Upload an APK")

        tab_upload, tab_path = st.tabs(["📁 File Upload", "🗂️ Server-side Path"])

        # Shared option: skip AI analysis
        skip_ai = not api_key or st.checkbox(
            "Skip AI analysis (raw findings only — no API key needed)",
            value=not api_key,
            disabled=not api_key,
            help="Runs checks 1–5 locally and shows raw grep results. No Claude API call is made.",
        )

        with tab_upload:
            uploaded = st.file_uploader(
                "Drop your .apk here",
                type=["apk"],
                help="Max 250 MB",
            )
            if uploaded and st.button("Analyze", key="btn_upload", type="primary"):
                with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name
                try:
                    st.session_state.apk_name = uploaded.name
                    st.session_state.verdict = run_analysis(tmp_path, skip_ai=skip_ai)
                    st.rerun()
                except Exception as exc:
                    st.error(f"Analysis failed: {exc}")
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        with tab_path:
            path_val = st.text_input(
                "APK file path (server-side)",
                placeholder="/path/to/app.apk",
            )
            if st.button("Analyze", key="btn_path", type="primary", disabled=not path_val):
                if not os.path.isfile(path_val):
                    st.error(f"File not found: {path_val}")
                else:
                    try:
                        st.session_state.apk_name = os.path.basename(path_val)
                        st.session_state.verdict = run_analysis(path_val, skip_ai=skip_ai)
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Analysis failed: {exc}")

    # ── Results section ───────────────────────────────────────────────────────
    else:
        st.caption(f"Results for: **{st.session_state.apk_name or 'uploaded APK'}**")
        if st.button("← Analyze another APK"):
            st.session_state.verdict = None
            st.session_state.apk_name = None
            st.rerun()

        v = st.session_state.verdict
        if v.get("__raw__"):
            render_raw_findings(v["findings"])
        else:
            render_results(v)


if __name__ == "__main__":
    main()
