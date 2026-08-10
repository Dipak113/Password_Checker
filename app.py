from datetime import datetime
from hashlib import sha256
from pathlib import Path
from time import sleep

import streamlit as st

import password_checker as pc

st.set_page_config(
    page_title="J.A.R.V.I.S. // Password Security Core",
    page_icon="🛡️",
    layout="wide",
)


def load_css(path):
    st.markdown(f"<style>{Path(path).read_text()}</style>", unsafe_allow_html=True)


load_css(Path(__file__).parent / "style.css")


# ---------------------------------------------------------------------------
# Boot sequence — plays once per session
# ---------------------------------------------------------------------------

if "booted" not in st.session_state:
    boot_lines = [
        "> INITIALIZING J.A.R.V.I.S. SECURITY CORE...",
        "> LOADING THREAT INTELLIGENCE DATABASE...",
        "> CALIBRATING ENTROPY ANALYSIS ENGINE...",
        "> ENCRYPTION MODULES: ONLINE",
        "> ALL SYSTEMS NOMINAL. STANDING BY.",
    ]
    boot_box = st.empty()
    rendered = ""
    for line in boot_lines:
        rendered += line + "<br>"
        boot_box.markdown(f"<pre class='boot-console'>{rendered}</pre>", unsafe_allow_html=True)
        sleep(0.3)
    sleep(0.4)
    boot_box.empty()
    st.session_state["booted"] = True


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown(
    "<div class='status-pill'><span class='status-dot'></span>ANALYSIS ENGINE: ACTIVE</div>",
    unsafe_allow_html=True,
)
st.title("🛡️ Password Security Core")
st.caption("Just A Rather Very Intelligent System · Real-time credential threat analysis.")

main_col, side_col = st.columns([2, 1], gap="large")


# ---------------------------------------------------------------------------
# Generator callback — must run before the password widget is instantiated,
# so it's wired via on_click rather than mutated inline.
# ---------------------------------------------------------------------------

def _generate_and_fill():
    generated = pc.generate_password(
        length=st.session_state.get("gen_length", 16),
        use_upper=st.session_state.get("gen_upper", True),
        use_lower=st.session_state.get("gen_lower", True),
        use_digits=st.session_state.get("gen_digits", True),
        use_special=st.session_state.get("gen_special", True),
    )
    st.session_state["password_input"] = generated
    st.session_state["last_generated"] = generated


def _clear_all():
    st.session_state["activity_log"] = []
    st.session_state["_last_hash"] = None
    st.session_state["password_input"] = ""
    st.session_state["last_generated"] = None


# ---------------------------------------------------------------------------
# Main column — password input + live analysis report
# ---------------------------------------------------------------------------

with main_col:
    st.markdown("<div class='hud-label'>◈ CREDENTIAL INPUT</div>", unsafe_allow_html=True)
    password = st.text_input(
        "Password",
        type="password",
        autocomplete="new-password",
        placeholder="Type or generate a password to scan...",
        key="password_input",
        label_visibility="collapsed",
    )

    if password:
        result = pc.check_password(password)
        analysis = result["analysis"]
        strength = result["strength"]
        score = result["score"]

        # Log this scan once per distinct password (avoid duplicate entries on
        # unrelated reruns, e.g. toggling a generator checkbox).
        st.session_state.setdefault("activity_log", [])
        pwd_hash = sha256(password.encode()).hexdigest()
        if st.session_state.get("_last_hash") != pwd_hash:
            st.session_state["_last_hash"] = pwd_hash
            st.session_state["activity_log"].insert(0, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "strength": strength,
                "score": score,
            })
            st.session_state["activity_log"] = st.session_state["activity_log"][:12]

        # ---- Strength banner ----
        strength_style = {
            "Weak": ("🔴", "error"),
            "Medium": ("🟡", "warning"),
            "Strong": ("🟢", "success"),
        }
        emoji, banner_fn = strength_style[strength]
        getattr(st, banner_fn)(f"{emoji} Password strength: **{strength}**  (score {score}/6)")
        st.progress(min(score, 6) / 6)

        if result["is_common"]:
            st.error("⚠️ THREAT DATABASE MATCH — this password appears on common breached-password lists. Avoid it entirely.")

        # ---- Stat tiles ----
        c1, c2, c3 = st.columns(3)
        c1.metric("Threat Score", f"{score}/6")
        c2.metric("Entropy", f"{result['entropy_bits']:.1f} bits")
        c3.metric("Est. Crack Time", result["crack_time_display"].upper())

        st.write("")
        st.markdown("<div class='hud-label'>◈ RULE CHECKLIST</div>", unsafe_allow_html=True)

        def rule_row(label, passed):
            icon = "✅" if passed else "❌"
            st.markdown(f"{icon} {label}")

        rule_row(f"At least {pc.MIN_LENGTH} characters (current: {analysis['length']})", analysis["length_ok"])
        rule_row("Contains an uppercase letter (A-Z)", analysis["has_upper"])
        rule_row("Contains a lowercase letter (a-z)", analysis["has_lower"])
        rule_row("Contains a number (0-9)", analysis["has_digit"])
        rule_row("Contains a special character (! @ # $ % ...)", analysis["has_special"])

        # ---- Suggestions ----
        if strength != "Strong":
            st.write("")
            st.markdown("<div class='hud-label'>◈ RECOMMENDED ACTIONS</div>", unsafe_allow_html=True)
            for tip in result["suggestions"]:
                st.markdown(f"- {tip}")
        else:
            st.write("")
            st.success("This password meets all the checks below. Nice work! 👍")

    else:
        st.info("Awaiting input — start typing or generate a key to begin the scan.")

    with st.expander("How is strength calculated?"):
        st.markdown(
            f"""
            Each password earns up to **6 points**:

            - 1 point for each of: length ≥ {pc.MIN_LENGTH}, an uppercase letter,
              a lowercase letter, a number, and a special character (5 points total)
            - 1 bonus point if the password is {pc.STRONG_LENGTH}+ characters long

            | Score | Classification |
            |---|---|
            | 0 – 2 | 🔴 Weak |
            | 3 – 4 | 🟡 Medium |
            | 5 – 6 | 🟢 Strong |

            **Entropy** is estimated from the character pool the password draws
            from (lowercase, uppercase, digits, symbols) — more available
            characters and greater length mean more possible combinations.

            **Est. crack time** assumes an offline attacker at
            {pc.GUESSES_PER_SECOND:,} guesses/second, a illustrative figure for
            comparison only — not a guarantee.
            """
        )


# ---------------------------------------------------------------------------
# Side column — key generator + activity log
# ---------------------------------------------------------------------------

with side_col:
    with st.container(border=True):
        st.markdown("<div class='hud-label'>🔑 SECURE KEY GENERATOR</div>", unsafe_allow_html=True)
        st.slider("Length", min_value=8, max_value=64, value=16, key="gen_length")
        gc1, gc2 = st.columns(2)
        gc1.checkbox("A-Z", value=True, key="gen_upper")
        gc1.checkbox("a-z", value=True, key="gen_lower")
        gc2.checkbox("0-9", value=True, key="gen_digits")
        gc2.checkbox("!@#", value=True, key="gen_special")
        st.button("⚡ Generate Secure Key", on_click=_generate_and_fill, use_container_width=True)

        if st.session_state.get("last_generated") and st.session_state.get("password_input") == st.session_state["last_generated"]:
            st.code(st.session_state["last_generated"], language=None)
            st.caption("Loaded into the scanner above. Click the block to copy.")

    st.write("")

    with st.container(border=True):
        st.markdown("<div class='hud-label'>📡 SYSTEM ACTIVITY LOG</div>", unsafe_allow_html=True)
        log = st.session_state.get("activity_log", [])
        if not log:
            st.caption("No scans recorded this session.")
        else:
            color_map = {"Weak": "#ff3b3b", "Medium": "#ffb300", "Strong": "#00ff9d"}
            lines = "".join(
                f"<div class='log-line' style='color:{color_map.get(e['strength'], '#d6f6ff')}'>"
                f"[{e['time']}] SCAN COMPLETE — {e['strength'].upper()} ({e['score']}/6)</div>"
                for e in log
            )
            st.markdown(f"<div class='log-panel'>{lines}</div>", unsafe_allow_html=True)
            st.button("🗑 Clear Log", on_click=_clear_all, use_container_width=True)
