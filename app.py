import re
import streamlit as st
from typing import List, Set

st.set_page_config(page_title="Cyber Threat Detection", layout="wide")

suspicious_patterns = [
    r"failed login",
    r"failed password",
    r"authentication failure",
    r"unauthorized access",
    r"multiple failed logins",
    r"invalid user",
    r"root login",
    r"sql injection",
    r"brute force",
    r"password spraying",
    r"attack detected",
    r"exploit",
]

email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
url_pattern = re.compile(r"https?://[\w./\-]+|www\.[\w./\-]+", re.IGNORECASE)
phone_pattern = re.compile(r"\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)?\d{3}[ -]?\d{4}\b")
ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

SCAM_PHONE_NUMBERS = {
    # United States scam numbers
    "18005550199",
    "18005550135",
    "18882045614",
    "18882200446",
    "18553787543",
    "18668626026",

    # Australian scam numbers
    "18001234567",
    "1300123456",
    "18008765432",
    "1300661701",
    "61412345678",
}

DEFAULT_IOCS = [
    "192.0.2.1",
    "198.51.100.2",
    "malicious.example.com",
    "badguy@example.com",
    "evil.local",
]


def normalize_phone(phone: str) -> str:
    return re.sub(r"\D", "", phone)


def detect_threats(text: str, custom_iocs: Set[str]) -> List[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    ioc_set = set(custom_iocs) | set(DEFAULT_IOCS)
    custom_phone_iocs = {normalize_phone(ioc) for ioc in custom_iocs if normalize_phone(ioc)}
    findings = []

    for line in lines:
        reasons = []
        lower_line = line.lower()

        if any(re.search(pattern, lower_line) for pattern in suspicious_patterns):
            reasons.append("pattern")

        if email_pattern.search(line):
            reasons.append("email")

        if url_pattern.search(line):
            reasons.append("url")

        phone_matches = phone_pattern.findall(line)
        for phone in phone_matches:
            normalized_phone = normalize_phone(phone)
            if normalized_phone in SCAM_PHONE_NUMBERS or normalized_phone in custom_phone_iocs:
                reasons.append("scammer-phone")
            else:
                reasons.append("phone")

        for ip in ip_pattern.findall(line):
            if ip in ioc_set:
                reasons.append("ioc")
            else:
                reasons.append("ip")

        for ioc in ioc_set:
            if ioc and ioc in line:
                reasons.append("ioc")

        if reasons:
            severity = "LOW"
            if "scammer-phone" in reasons or "ioc" in reasons or ("pattern" in reasons and ("ip" in reasons or "email" in reasons or "url" in reasons)):
                severity = "HIGH"
            elif "pattern" in reasons or "url" in reasons:
                severity = "MEDIUM"

            reasons = sorted(set(reasons))
            findings.append(f"[{severity}] {', '.join(reasons)}: {line}")

    return findings


def main():
    st.title("Cyber Threat Detection")
    st.write("Upload logs or paste raw text to identify suspicious activity, IOCs, and anomalous entries.")

    with st.sidebar:
        st.header("Detection Settings")
        custom_ioc_input = st.text_area(
            "Custom IOCs (one per line)",
            placeholder="192.0.2.123\nmalicious.example.net\nattacker@example.com\n+1 800 555 0199",
            help="Add IP addresses, domains, hostnames, email addresses, or phone numbers to detect known bad indicators.",
            height=150,
        )

        show_rules = st.checkbox("Show detection rules", value=True)
        if show_rules:
            st.markdown(
                """
                - Suspicious authentication failures and login anomalies
                - Known IOC matches for IPs, domains, email addresses, and phone numbers
                - Malicious URLs, suspicious identifiers, and possible brute-force activity
                - Known scam phone number detection for reported scammer contacts
                """
            )

    st.markdown("### Input logs")
    raw_text = st.text_area("Paste raw log content here", height=250)
    uploaded_file = st.file_uploader("Upload a log file", type=["log", "txt"])

    uploaded_text = ""
    if uploaded_file is not None:
        uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")

    source_text = "\n".join([raw_text, uploaded_text]).strip()
    custom_iocs = {ioc.strip() for ioc in custom_ioc_input.splitlines() if ioc.strip()}

    if st.button("Run Threat Detection"):
        if not source_text:
            st.warning("Please provide log text or upload a log file before running detection.")
            return

        results = detect_threats(source_text, custom_iocs)
        counts = {
            "HIGH": sum(1 for item in results if item.startswith("[HIGH]")),
            "MEDIUM": sum(1 for item in results if item.startswith("[MEDIUM]")),
            "LOW": sum(1 for item in results if item.startswith("[LOW]")),
        }

        st.success(f"Detected {len(results)} suspicious entries")
        col1, col2, col3 = st.columns(3)
        col1.metric("High", counts["HIGH"], delta="+{}".format(counts["HIGH"]))
        col2.metric("Medium", counts["MEDIUM"], delta="+{}".format(counts["MEDIUM"]))
        col3.metric("Low", counts["LOW"], delta="+{}".format(counts["LOW"]))

        with st.expander("View threat details", expanded=True):
            for result in results:
                st.code(result)

        if custom_iocs:
            st.info(f"Using {len(custom_iocs)} custom IOC(s) for detection")

    if source_text:
        with st.expander("Preview parsed input", expanded=False):
            st.text_area("Log preview", value=source_text, height=200)


if __name__ == "__main__":
    main()
