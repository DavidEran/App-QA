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


def _assemble_findings(apk_path, size_info, perm_info, integrity_info, privacy_info, policy_text):
    return {
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


def run_analysis(apk_path: str) -> dict:
    """Run all 6 checks and Claude API call, updating Streamlit status live."""
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

        st.write("🤖 **Calling Claude API** for structured analysis…")
        findings = _assemble_findings(
            apk_path, size_info, perm_info, integrity_info, privacy_info, policy_text
        )
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
            "⚠️ `ANTHROPIC_API_KEY` not set. "
            "Add it to `.streamlit/secrets.toml` or as an environment variable.",
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

        with tab_upload:
            uploaded = st.file_uploader(
                "Drop your .apk here",
                type=["apk"],
                help="Max 250 MB",
            )
            if uploaded and st.button("Analyze", key="btn_upload", type="primary", disabled=not api_key):
                with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name
                try:
                    st.session_state.apk_name = uploaded.name
                    st.session_state.verdict = run_analysis(tmp_path)
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
            if st.button("Analyze", key="btn_path", type="primary", disabled=not (api_key and path_val)):
                if not os.path.isfile(path_val):
                    st.error(f"File not found: {path_val}")
                else:
                    try:
                        st.session_state.apk_name = os.path.basename(path_val)
                        st.session_state.verdict = run_analysis(path_val)
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

        render_results(st.session_state.verdict)


if __name__ == "__main__":
    main()
