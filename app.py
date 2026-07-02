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
    r"password spraying",import csv
import io
import re
import os
import base64
import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import streamlit as st
from typing import Dict, List, Set

st.set_page_config(page_title="Jarvis Cyber Threat Detection", layout="wide")

# Theme CSS - Modern & Sophisticated
st.markdown(
    """
    <style>
    * { margin: 0; padding: 0; }
    body { background-color: #0a0e27; color: #e0e7ff; font-family: 'Segoe UI', 'Roboto', sans-serif; }
    .stApp { 
        background: linear-gradient(135deg, #0f1629 0%, #16213e 25%, #0f3460 50%, #16213e 75%, #0a0e27 100%);
        background-attachment: fixed;
    }
    .jarvis-title { 
        font-size: 3.8rem; 
        background: linear-gradient(135deg, #00d4ff 0%, #0099ff 50%, #6366f1 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 900;
        letter-spacing: -1px;
        text-shadow: 0 10px 30px rgba(0, 212, 255, 0.2);
    }
    .jarvis-subtitle {
        color: #a5f3fc;
        font-size: 1.2rem;
        font-weight: 300;
        letter-spacing: 0.5px;
    }
    .jarvis-panel { 
        border-radius: 20px; 
        padding: 28px; 
        margin-bottom: 20px; 
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 58, 138, 0.3) 100%);
        border: 1px solid rgba(0, 212, 255, 0.15);
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
    }
    .plan-card { 
        border-radius: 24px; 
        padding: 32px; 
        color: #f1f5f9; 
        margin-bottom: 16px; 
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(56, 189, 248, 0.2);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        backdrop-filter: blur(10px);
        position: relative;
        overflow: hidden;
    }
    .plan-card:hover {
        transform: translateY(-8px);
        box-shadow: 0 40px 80px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.15);
        border-color: rgba(0, 212, 255, 0.4);
    }
    .plan-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
        transition: left 0.5s;
    }
    .plan-card:hover::before { left: 100%; }
    .plan-free { background: linear-gradient(135deg, rgba(30, 40, 70, 0.8), rgba(20, 30, 60, 0.8)); }
    .plan-start { background: linear-gradient(135deg, rgba(2, 72, 255, 0.15), rgba(59, 130, 246, 0.1)); border-color: rgba(59, 130, 246, 0.3); }
    .plan-premium { 
        background: linear-gradient(135deg, rgba(124, 58, 237, 0.2), rgba(168, 85, 247, 0.1)); 
        border-color: rgba(168, 85, 247, 0.4);
        box-shadow: 0 25px 50px rgba(168, 85, 247, 0.15), 0 0 60px rgba(168, 85, 247, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    }
    .plan-premium:hover {
        box-shadow: 0 40px 80px rgba(168, 85, 247, 0.25), 0 0 80px rgba(168, 85, 247, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }
    .input-card {
        border-radius: 18px;
        padding: 24px;
        background: linear-gradient(135deg, rgba(20, 30, 60, 0.7), rgba(30, 40, 80, 0.5));
        border: 1px solid rgba(0, 212, 255, 0.1);
        box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(5px);
        margin-bottom: 16px;
    }
    h1, h2, h3, h4, h5, h6 {
        background: linear-gradient(135deg, #00d4ff, #0099ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Detection Patterns
suspicious_patterns = [
    r"failed login", r"failed password", r"authentication failure", r"unauthorized access",
    r"sql injection", r"brute force", r"credential stuffing", r"data exfiltration", r"malware", r"phishing",
]
compiled_patterns = [re.compile(p, re.IGNORECASE) for p in suspicious_patterns]
email_pattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
url_pattern = re.compile(r"https?://[\w./\-]+|www\.[\w./\-]+", re.IGNORECASE)
phone_pattern = re.compile(r"\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{2,3}\)?[ -]?)?\d{3}[ -]?\d{4}\b")
ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

SCAM_PHONE_NUMBERS = {
    "18005550199", "18005550135", "18882045614", "18882200446", "18553787543", "18668626026",
    "18001234567", "1300123456", "18008765432", "1300661701", "61412345678",
}
DEFAULT_IOCS = ["192.0.2.1", "198.51.100.2", "malicious.example.com", "badguy@example.com", "evil.local"]

# Notification management
NOTIFICATIONS_FILE = "notifications.json"
SUBSCRIBERS_FILE = "subscriptions.txt"
USERS_FILE = "users.json"

# Default admin credentials (change these!)
DEFAULT_ADMIN = {
    "username": "admin",
    "password": "jarvis2024"  # Change this!
}

# Email Configuration - You can modify these
EMAIL_CONFIG = {
    "sender_email": os.getenv("JARVIS_EMAIL", "jarvis.cyber.threat@gmail.com"),
    "sender_password": os.getenv("JARVIS_PASSWORD", ""),  # Set via environment variable for security
    "smtp_server": os.getenv("JARVIS_SMTP", "smtp.gmail.com"),
    "smtp_port": int(os.getenv("JARVIS_SMTP_PORT", "587")),
}


def load_users() -> Dict:
    """Load user credentials from file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    # Initialize with default admin
    users = {DEFAULT_ADMIN["username"]: DEFAULT_ADMIN["password"]}
    save_users(users)
    return users


def save_users(users: Dict) -> None:
    """Save user credentials to file."""
    try:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
    except Exception:
        pass


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user credentials."""
    users = load_users()
    return users.get(username) == password


def register_user(username: str, password: str) -> bool:
    """Register a new user (admin only)."""
    if not username or not password or len(password) < 6:
        return False
    
    users = load_users()
    if username in users:
        return False
    
    users[username] = password
    save_users(users)
    save_notification("user_registration", f"New user registered: {username}")
    return True


def send_email(recipient: str, subject: str, body: str, html_body: str = None) -> bool:
    """Send an email notification."""
    try:
        if not EMAIL_CONFIG["sender_password"]:
            # Email sending disabled if no password configured
            return False
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_CONFIG["sender_email"]
        msg["To"] = recipient
        
        # Attach text version
        msg.attach(MIMEText(body, "plain"))
        
        # Attach HTML version if provided
        if html_body:
            msg.attach(MIMEText(html_body, "html"))
        
        # Send via SMTP
        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
            server.sendmail(EMAIL_CONFIG["sender_email"], recipient, msg.as_string())
        
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


def send_welcome_email(email: str) -> None:
    """Send welcome email to new subscriber."""
    subject = "Welcome to JARVIS - Cyber Threat Detection"
    
    body = f"""Welcome to JARVIS!

You've successfully subscribed to threat alerts.

When critical threats are detected, you'll receive instant notifications at this email address ({email}).

Threat Alert Features:
- Real-time threat detection notifications
- Threat severity levels (Critical, Medium, Low)
- IOC and scam phone detection alerts
- Automated security updates

To configure your email or unsubscribe, visit the JARVIS dashboard.

Stay Secure,
JARVIS Team
"""
    
    html_body = f"""
    <html>
        <body style='font-family: Arial, sans-serif; background: #0a0e27; color: #e0e7ff;'>
            <div style='max-width: 600px; margin: 0 auto; padding: 30px; background: rgba(15,23,42,0.8); border-radius: 12px; border: 1px solid rgba(0,212,255,0.2);'>
                <h1 style='color: #00d4ff; margin-bottom: 20px;'>Welcome to JARVIS 🛡️</h1>
                <p style='color: #a5f3fc; font-size: 16px; line-height: 1.6;'>
                    You've successfully subscribed to threat alerts!
                </p>
                <p style='color: #a5f3fc; font-size: 16px; line-height: 1.6;'>
                    When critical threats are detected, you'll receive instant notifications at <strong>{email}</strong>
                </p>
                <div style='background: rgba(0,212,255,0.1); padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #00d4ff;'>
                    <h3 style='color: #00d4ff; margin-top: 0;'>✓ What You'll Receive</h3>
                    <ul style='color: #c7d2fe;'>
                        <li>Real-time threat detection notifications</li>
                        <li>Threat severity levels (Critical, Medium, Low)</li>
                        <li>IOC and scam phone detection alerts</li>
                        <li>Automated security updates</li>
                    </ul>
                </div>
                <p style='color: #888; font-size: 12px; margin-top: 30px;'>
                    To configure your email or unsubscribe, visit the JARVIS dashboard.
                </p>
            </div>
        </body>
    </html>
    """
    
    send_email(email, subject, body, html_body)


def load_notifications() -> List[Dict]:
    """Load notifications from file."""
    if os.path.exists(NOTIFICATIONS_FILE):
        try:
            with open(NOTIFICATIONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_notification(notification_type: str, message: str, recipient: str = "all") -> None:
    """Save a notification to file."""
    notifications = load_notifications()
    notifications.append({
        "type": notification_type,
        "message": message,
        "recipient": recipient,
        "timestamp": datetime.now().isoformat(),
    })
    # Keep only last 100 notifications
    notifications = notifications[-100:]
    try:
        with open(NOTIFICATIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(notifications, f, indent=2)
    except Exception:
        pass


def load_subscribers() -> List[str]:
    """Load list of subscribers."""
    if os.path.exists(SUBSCRIBERS_FILE):
        try:
            with open(SUBSCRIBERS_FILE, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            return []
    return []


def add_subscriber(email: str) -> bool:
    """Add a new subscriber and send welcome email."""
    if not email or "@" not in email:
        return False
    
    subscribers = load_subscribers()
    if email in subscribers:
        return False
    
    try:
        with open(SUBSCRIBERS_FILE, "a", encoding="utf-8") as f:
            f.write(email + "\n")
        
        # Create notification for subscription
        save_notification(
            "subscription",
            f"New subscriber: {email}",
            recipient=email
        )
        
        # Send welcome email
        send_welcome_email(email)
        
        return True
    except Exception:
        return False


def normalize_phone(phone: str) -> str:
    return re.sub(r"\D", "", phone)


def is_scam_phone(phone: str, custom_phone_iocs: Set[str]) -> bool:
    normalized = normalize_phone(phone)
    return normalized in SCAM_PHONE_NUMBERS or normalized in custom_phone_iocs


def detect_threats(text: str, custom_iocs: Set[str]) -> List[Dict[str, str]]:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    ioc_set = set(custom_iocs) | set(DEFAULT_IOCS)
    custom_phone_iocs = {normalize_phone(i) for i in custom_iocs if normalize_phone(i)}
    findings: List[Dict[str, str]] = []
    for line in lines:
        reasons = set()
        entities = {
            "emails": email_pattern.findall(line),
            "urls": url_pattern.findall(line),
            "phones": phone_pattern.findall(line),
            "ips": ip_pattern.findall(line),
        }
        if any(p.search(line) for p in compiled_patterns):
            reasons.add("pattern")
        if entities["emails"]:
            reasons.add("email")
        if entities["urls"]:
            reasons.add("url")
        for ph in entities["phones"]:
            reasons.add("scammer-phone" if is_scam_phone(ph, custom_phone_iocs) else "phone")
        for ip in entities["ips"]:
            reasons.add("ioc" if ip in ioc_set else "ip")
        for ioc in ioc_set:
            if ioc and ioc in line:
                reasons.add("ioc")
        if reasons:
            severity = "LOW"
            if "scammer-phone" in reasons or "ioc" in reasons or ("pattern" in reasons and ("ip" in reasons or "email" in reasons or "url" in reasons)):
                severity = "HIGH"
            elif "pattern" in reasons or "url" in reasons:
                severity = "MEDIUM"
            findings.append({
                "line": line,
                "severity": severity,
                "reasons": ", ".join(sorted(reasons)),
                "emails": ", ".join(entities["emails"]),
                "urls": ", ".join(entities["urls"]),
                "phones": ", ".join(entities["phones"]),
                "ips": ", ".join(entities["ips"]),
            })
    return findings


def create_csv(findings: List[Dict[str, str]]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["severity", "reasons", "line", "emails", "urls", "phones", "ips"])
    writer.writeheader()
    for f in findings:
        writer.writerow(f)
    return out.getvalue()


def show_jarvis_splash() -> None:
    """Display Jarvis startup splash screen when users sign in."""
    image_paths = [os.path.join("assets", "jarvis_splash.png"), "jarvis_splash.png"]
    found_image = next((p for p in image_paths if os.path.exists(p)), None)

    st.markdown("""
        <style>
        .jarvis-image { 
            max-width:540px; 
            width:72vw; 
            border-radius: 24px;
            box-shadow: 0 0 100px rgba(0, 212, 255, 0.3), 0 0 200px rgba(99, 102, 241, 0.1);
            border: 2px solid rgba(0, 212, 255, 0.3);
            animation: floaty 4s ease-in-out infinite, spin 12s linear infinite, glow 3s ease-in-out infinite;
        }
        @keyframes floaty { 
            0%{transform:translateY(0) scale(1)} 
            50%{transform:translateY(-15px) scale(1.03)} 
            100%{transform:translateY(0) scale(1)} 
        }
        @keyframes spin { 
            0%{transform:rotate(0deg)} 
            100%{transform:rotate(360deg)} 
        }
        @keyframes glow {
            0%, 100%{box-shadow: 0 0 100px rgba(0, 212, 255, 0.3), 0 0 200px rgba(99, 102, 241, 0.1)}
            50%{box-shadow: 0 0 150px rgba(0, 212, 255, 0.5), 0 0 300px rgba(99, 102, 241, 0.2)}
        }
        .splash-container {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #0f1629 0%, #16213e 50%, #0a0e27 100%);
        }
        .splash-content {
            text-align: center;
            animation: fadeInUp 1s ease-out;
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .jarvis-enter-btn {
            margin-top: 3rem;
            padding: 16px 48px;
            font-weight: 800;
            font-size: 1.1rem;
            border-radius: 50px;
            background: linear-gradient(135deg, #00d4ff 0%, #0099ff 50%, #6366f1 100%);
            color: #0a0e27;
            border: none;
            cursor: pointer;
            box-shadow: 0 10px 40px rgba(0, 212, 255, 0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            letter-spacing: 1px;
        }
        .jarvis-enter-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 20px 60px rgba(0, 212, 255, 0.5);
        }
        .jarvis-enter-btn:active {
            transform: translateY(-1px);
        }
        </style>
    """, unsafe_allow_html=True)

    if found_image:
        try:
            with open(found_image, "rb") as f:
                img_b64 = base64.b64encode(f.read()).decode("ascii")
            html = (
                "<div class='splash-container'>"
                "<div class='splash-content'>"
                "<img class='jarvis-image' src='data:image/png;base64," + img_b64 + "' />"
                "</div>"
                "</div>"
            )
            st.markdown(html, unsafe_allow_html=True)
        except Exception:
            st.markdown("""
                <div style='text-align:center; padding:4rem; min-height: 100vh; display:flex; align-items:center; justify-content:center;'>
                    <div style='animation: fadeInUp 1s ease-out;'>
                        <h1 style='font-size:4.5rem; margin-bottom:1rem;'>JARVIS</h1>
                        <p style='color:#a5f3fc; font-size:1.3rem; font-weight:300; letter-spacing:2px;'>NEURAL NETWORK ACTIVATED</p>
                    </div>
                </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
            <div style='text-align:center; padding:4rem; min-height: 100vh; display:flex; align-items:center; justify-content:center;'>
                <div style='animation: fadeInUp 1s ease-out;'>
                    <h1 style='font-size:4.5rem; margin-bottom:1.5rem;'>JARVIS</h1>
                    <p style='color:#a5f3fc; font-size:1.3rem; font-weight:300; letter-spacing:2px; margin-bottom:2rem;'>CYBER THREAT DETECTION SYSTEM</p>
                    <div style='font-family:Courier, monospace; color:#00d4ff; font-size:0.95rem; line-height:1.8;'>
                        <div>━ SYSTEM STATUS: <strong style='color:#0099ff;'>BOOT SEQUENCE ACTIVE</strong></div>
                        <div>━ SECURITY MODULES: <strong style='color:#0099ff;'>ENGAGED</strong></div>
                        <div>━ THREAT GRID: <strong style='color:#0099ff;'>ONLINE</strong></div>
                        <div>━ SCAN NETWORK: <strong style='color:#0099ff;'>READY</strong></div>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("ENTER JARVIS", key="enter_jarvis", use_container_width=True):
            st.session_state.jarvis_started = True
            st.rerun()


def show_dashboard(custom_ioc_input: str) -> None:
    """Display the main threat detection dashboard."""
    subscribers = load_subscribers()
    
    st.markdown(f"""
        <div class='jarvis-panel'>
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <div>
                    <div class='jarvis-title'>◆ JARVIS ◆</div>
                    <p style='color:#a5f3fc; font-size:1.1rem; margin-top:1rem; font-weight:300; letter-spacing:0.5px;'>
                        Advanced Cyber Threat Intelligence & IOC Detection Platform
                    </p>
                </div>
                <div style='text-align: right; background: rgba(0,212,255,0.1); padding: 16px; border-radius: 12px; border: 1px solid rgba(0,212,255,0.2);'>
                    <p style='color: #00d4ff; font-size: 0.9rem; margin: 0; font-weight: 600;'>📊 Active Subscribers</p>
                    <p style='color: #a5f3fc; font-size: 1.8rem; font-weight: 800; margin: 4px 0 0 0;'>{len(subscribers)}</p>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    with st.sidebar:
        # User info and logout
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"<p style='color: #00d4ff; font-weight: 600; margin: 10px 0;'>👤 {st.session_state.get('username', 'User')}</p>", unsafe_allow_html=True)
        with col2:
            if st.button("🔒 Logout", key="logout_btn", help="Sign out and return to login"):
                st.session_state.logged_in = False
                st.session_state.username = None
                st.session_state.jarvis_started = False
                st.rerun()
        
        st.divider()
        
        st.markdown("<div style='padding: 20px 0;'></div>", unsafe_allow_html=True)
        st.markdown("<h2 style='color: #00d4ff; font-size:1.4rem; margin-bottom: 24px;'>⚙️ Detection Settings</h2>", unsafe_allow_html=True)
        
        # Email Configuration
        with st.expander("📧 Email Configuration", expanded=False):
            st.markdown("<p style='color: #a5f3fc; font-size: 0.9rem; margin-bottom: 12px;'><strong>Configure email alerts:</strong></p>", unsafe_allow_html=True)
            
            if not EMAIL_CONFIG["sender_password"]:
                st.warning("""
                    ⚠️ **Email alerts not configured**
                    
                    To enable email notifications, set environment variables:
                    - `JARVIS_EMAIL` (your email)
                    - `JARVIS_PASSWORD` (app password or token)
                    - `JARVIS_SMTP` (SMTP server, default: smtp.gmail.com)
                    - `JARVIS_SMTP_PORT` (SMTP port, default: 587)
                    
                    For Gmail: Use an [App Password](https://myaccount.google.com/apppasswords)
                """)
            else:
                st.success(f"✓ Email configured: {EMAIL_CONFIG['sender_email']}")
        
        st.markdown("<div class='input-card'>", unsafe_allow_html=True)
        custom_ioc_input = st.text_area(
            "Custom IOCs (one per line)",
            value=custom_ioc_input,
            height=140,
            placeholder="192.0.2.123\nmalicious.com\nattacker@evil.com",
            key="custom_ioc_input",
        )
        st.markdown("</div>", unsafe_allow_html=True)

        show_ioc_list = st.checkbox("📋 Show built-in IOC and scam lists", value=False)
        if show_ioc_list:
            st.markdown("""
                <div style='background: rgba(0,212,255,0.05); padding: 16px; border-radius: 12px; border-left: 3px solid #00d4ff; margin: 12px 0;'>
                    <p style='color: #00d4ff; font-weight: bold; margin-bottom: 8px;'>Built-in IOCs</p>
                    <p style='color: #a5f3fc; font-size: 0.9rem;'>192.0.2.1, 198.51.100.2, malicious.example.com</p>
                </div>
            """, unsafe_allow_html=True)
            st.markdown("""
                <div style='background: rgba(255,69,0,0.08); padding: 16px; border-radius: 12px; border-left: 3px solid #ff4500; margin: 12px 0;'>
                    <p style='color: #ff7f50; font-weight: bold; margin-bottom: 8px;'>🚨 Scam Phones (Sample)</p>
                    <p style='color: #a5f3fc; font-size: 0.9rem;'>1-800-555-0199, 1-888-204-5614, 1-300-123-456</p>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("<hr style='border: 1px solid rgba(0,212,255,0.2); margin: 24px 0;'>", unsafe_allow_html=True)
        st.markdown("<h3 style='color: #00d4ff; font-size:1.2rem; margin-bottom: 16px;'>📧 Premium Alerts</h3>", unsafe_allow_html=True)
        
        st.markdown("<div class='input-card'>", unsafe_allow_html=True)
        subscription_email = st.text_input("Email address", placeholder="you@example.com", key="subscription_email")
        if st.button("✓ Subscribe", key="subscribe_button", use_container_width=True):
            if subscription_email:
                if add_subscriber(subscription_email):
                    st.toast("🎉 Subscribed successfully! You'll receive threat alerts.", icon="✓")
                    st.balloons()
                    st.markdown("""
                        <div class='jarvis-panel' style='background: rgba(34, 197, 94, 0.1); border-color: rgba(34, 197, 94, 0.3); margin-top: 12px;'>
                            <p style='color: #22c55e; margin: 0;'>✓ Subscription confirmed! Check your email for alerts.</p>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.warning("⚠ Email already subscribed or invalid")
                st.warning("⚠ Enter a valid email address")
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<hr style='border: 1px solid rgba(0,212,255,0.2); margin: 24px 0;'>", unsafe_allow_html=True)
        st.markdown("<h3 style='color: #00d4ff; font-size:1.2rem; margin-bottom: 16px;'>🔔 Recent Notifications</h3>", unsafe_allow_html=True)
        
        notifications = load_notifications()
        if notifications:
            # Show last 5 notifications
            recent = notifications[-5:][::-1]
            for notif in recent:
                notif_type = notif.get("type", "info")
                message = notif.get("message", "")
                timestamp = notif.get("timestamp", "")
                
                # Parse timestamp
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M:%S")
                except:
                    time_str = "N/A"
                
                icon = "✓" if notif_type == "subscription" else "🚨"
                color = "#22c55e" if notif_type == "subscription" else "#ff4444"
                
                st.markdown(f"""
                    <div style='background: rgba(255,255,255,0.03); padding: 8px; border-radius: 8px; border-left: 3px solid {color}; margin-bottom: 6px;'>
                        <p style='color: {color}; font-size: 0.8rem; margin: 0; font-weight: 600;'>{icon} {message}</p>
                        <p style='color: #666; font-size: 0.75rem; margin: 2px 0 0 0;'>{time_str}</p>
                    </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("<p style='color: #666; font-size: 0.9rem; margin: 0;'>No notifications yet</p>", unsafe_allow_html=True)

    st.markdown("---", unsafe_allow_html=True)
    st.markdown("<h3 style='color: #00d4ff; font-size:1.3rem; margin-bottom: 20px;'>📂 Input Logs & Files</h3>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<p style='color:#a5f3fc; font-size:0.95rem; font-weight:600; margin-bottom:8px;'>Paste Raw Log Content</p>", unsafe_allow_html=True)
        raw_text = st.text_area("Paste raw log data", height=220, key="raw_log_text", placeholder="Paste your log content here...", label_visibility="collapsed")
    
    with col2:
        st.markdown("<p style='color:#a5f3fc; font-size:0.95rem; font-weight:600; margin-bottom:8px;'>Upload Log File</p>", unsafe_allow_html=True)
        uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"], key="uploaded_log_file", label_visibility="collapsed")
        st.markdown("<p style='color:#888; font-size:0.85rem; margin-top:8px;'>Supported: .log, .txt</p>", unsafe_allow_html=True)

    uploaded_text = ""
    if uploaded_file is not None:
        uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")

    source_text = "\n".join([raw_text, uploaded_text]).strip()
    custom_iocs = {ioc.strip() for ioc in custom_ioc_input.splitlines() if ioc.strip()}

    st.markdown("---", unsafe_allow_html=True)
    st.markdown("<h3 style='color: #00d4ff; font-size:1.3rem; margin-bottom: 20px;'>🔍 Threat Analysis</h3>", unsafe_allow_html=True)

    if st.button("🚀 Run Threat Detection", key="run_detection", use_container_width=True):
        if not source_text:
            st.warning("⚠ Please paste logs or upload a file to begin scanning")
        else:
            with st.spinner("🔄 JARVIS is analyzing threat patterns..."):
                findings = detect_threats(source_text, custom_iocs)

            counts = {
                "HIGH": sum(1 for i in findings if i["severity"] == "HIGH"),
                "MEDIUM": sum(1 for i in findings if i["severity"] == "MEDIUM"),
                "LOW": sum(1 for i in findings if i["severity"] == "LOW"),
            }

            # Send notifications to all subscribers
            subscribers = load_subscribers()
            if subscribers and len(findings) > 0:
                alert_msg = f"THREAT ALERT: {len(findings)} threats detected ({counts['HIGH']} critical, {counts['MEDIUM']} medium)"
                save_notification("threat_alert", alert_msg, recipient="subscribers")
                
                # Send threat alert emails to all subscribers
                subject = f"🚨 JARVIS THREAT ALERT: {len(findings)} Threats Detected"
                
                body = f"""THREAT ALERT!

JARVIS has detected {len(findings)} suspicious entries in your scan.

Severity Breakdown:
- CRITICAL: {counts['HIGH']} threats
- MEDIUM: {counts['MEDIUM']} threats  
- LOW: {counts['LOW']} threats

Please review the JARVIS dashboard for detailed threat analysis.

Stay Alert,
JARVIS Threat Detection System
"""
                
                html_body = f"""
                <html>
                    <body style='font-family: Arial, sans-serif; background: #0a0e27; color: #e0e7ff;'>
                        <div style='max-width: 600px; margin: 0 auto; padding: 30px; background: rgba(15,23,42,0.8); border-radius: 12px; border: 2px solid #ff4444;'>
                            <h1 style='color: #ff4444; margin-bottom: 20px;'>🚨 THREAT ALERT</h1>
                            <p style='color: #ff6b6b; font-size: 18px; font-weight: bold; margin-bottom: 20px;'>
                                {len(findings)} Threats Detected
                            </p>
                            <div style='background: rgba(255,68,68,0.1); padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ff4444;'>
                                <h3 style='color: #ff6b6b; margin-top: 0;'>Severity Breakdown</h3>
                                <p style='color: #a5f3fc; font-size: 16px; margin: 8px 0;'>🔴 <strong>CRITICAL:</strong> {counts['HIGH']} threats</p>
                                <p style='color: #a5f3fc; font-size: 16px; margin: 8px 0;'>🟠 <strong>MEDIUM:</strong> {counts['MEDIUM']} threats</p>
                                <p style='color: #a5f3fc; font-size: 16px; margin: 8px 0;'>🔵 <strong>LOW:</strong> {counts['LOW']} threats</p>
                            </div>
                            <p style='color: #a5f3fc; margin-top: 20px;'>
                                Please review the JARVIS dashboard for detailed threat analysis and recommended actions.
                            </p>
                        </div>
                    </body>
                </html>
                """
                
                for subscriber in subscribers:
                    send_email(subscriber, subject, body, html_body)
                
                # Show toast for admin
                st.toast(f"📧 {len(subscribers)} subscriber(s) alerted via email!", icon="🔔")

            st.markdown("""
                <div class='jarvis-panel' style='text-align: center; margin-bottom: 24px;'>
                    <p style='color: #a5f3fc; font-size: 1.1rem; margin-bottom: 16px;'>
                        ✓ Analysis Complete
                    </p>
                    <h2 style='font-size: 2.5rem; background: linear-gradient(135deg, #ff4444, #ff8844); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
                        """ + str(len(findings)) + """ Threats Detected
                    </h2>
                </div>
            """, unsafe_allow_html=True)

            metric_col1, metric_col2, metric_col3 = st.columns(3)
            with metric_col1:
                st.markdown(f"""
                    <div class='jarvis-panel' style='text-align: center; border-left: 4px solid #ff4444;'>
                        <p style='color: #ff4444; font-size: 0.95rem; font-weight: 600; margin-bottom: 8px;'>🔴 CRITICAL</p>
                        <p style='font-size: 2.2rem; font-weight: 800; color: #ff4444;'>{counts["HIGH"]}</p>
                    </div>
                """, unsafe_allow_html=True)
            with metric_col2:
                st.markdown(f"""
                    <div class='jarvis-panel' style='text-align: center; border-left: 4px solid #ffa500;'>
                        <p style='color: #ffa500; font-size: 0.95rem; font-weight: 600; margin-bottom: 8px;'>🟠 WARNING</p>
                        <p style='font-size: 2.2rem; font-weight: 800; color: #ffa500;'>{counts["MEDIUM"]}</p>
                    </div>
                """, unsafe_allow_html=True)
            with metric_col3:
                st.markdown(f"""
                    <div class='jarvis-panel' style='text-align: center; border-left: 4px solid #00d4ff;'>
                        <p style='color: #00d4ff; font-size: 0.95rem; font-weight: 600; margin-bottom: 8px;'>🔵 INFO</p>
                        <p style='font-size: 2.2rem; font-weight: 800; color: #00d4ff;'>{counts["LOW"]}</p>
                    </div>
                """, unsafe_allow_html=True)

            if findings:
                st.markdown("<div style='margin-bottom: 24px;'></div>", unsafe_allow_html=True)
                col1, col2 = st.columns([2, 1])
                with col1:
                    st.download_button(
                        "📥 Download CSV Report",
                        create_csv(findings),
                        file_name="threat_findings.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )
                with col2:
                    st.markdown(f"<p style='color: #a5f3fc; text-align: right; padding-top: 10px;'>Custom IOCs: {len(custom_iocs)}</p>", unsafe_allow_html=True)

                st.markdown("""
                    <div class='jarvis-panel' style='margin-bottom: 20px;'>
                        <p style='color: #00d4ff; font-weight: 600; margin-bottom: 12px;'>📊 Threat Distribution</p>
                """, unsafe_allow_html=True)
                
                chart_data = {"Severity": [counts["HIGH"], counts["MEDIUM"], counts["LOW"]]}
                st.bar_chart(data=chart_data, height=300)
                st.markdown("</div>", unsafe_allow_html=True)

                with st.expander("📋 Detailed Threat Report", expanded=True):
                    st.dataframe(
                        [
                            {
                                "🔴 Severity": item["severity"],
                                "⚠️  Reasons": item["reasons"],
                                "📧 Emails": item["emails"],
                                "🔗 URLs": item["urls"],
                                "☎️ Phones": item["phones"],
                                "🖥️ IPs": item["ips"],
                                "📝 Line Content": item["line"][:80] + "..." if len(item["line"]) > 80 else item["line"],
                            }
                            for item in findings
                        ],
                        use_container_width=True,
                    )

                st.markdown("---", unsafe_allow_html=True)
                st.markdown("<h3 style='color: #00d4ff; font-size:1.2rem; margin-bottom: 20px;'>💼 Upgrade to Premium</h3>", unsafe_allow_html=True)
                
                plan_col1, plan_col2, plan_col3 = st.columns(3)

                with plan_col1:
                    st.markdown("""
                        <div class='plan-card plan-free'>
                            <h3 style='color: #00d4ff;'>Free Plan</h3>
                            <p style='font-size: 1.8rem; font-weight: 900; color: #a5f3fc; margin: 12px 0;'>$0</p>
                            <p style='color: #888; margin-bottom: 16px;'>One-time access</p>
                            <ul style='text-align: left; color: #c7d2fe; font-size: 0.95rem; line-height: 1.8;'>
                                <li>✓ Basic log scanning</li>
                                <li>✓ Core threat detection</li>
                                <li>✓ CSV export</li>
                                <li>✓ Demo access</li>
                            </ul>
                        </div>
                    """, unsafe_allow_html=True)

                with plan_col2:
                    st.markdown("""
                        <div class='plan-card plan-start'>
                            <h3 style='color: #3b82f6;'>Starter</h3>
                            <p style='font-size: 1.8rem; font-weight: 900; color: #60a5fa; margin: 12px 0;'>$79</p>
                            <p style='color: #888; margin-bottom: 16px;'>per month</p>
                            <ul style='text-align: left; color: #c7d2fe; font-size: 0.95rem; line-height: 1.8;'>
                                <li>✓ Custom IOC uploads</li>
                                <li>✓ Scheduled scans</li>
                                <li>✓ Phone scam detection</li>
                                <li>✓ Monthly reports</li>
                            </ul>
                        </div>
                    """, unsafe_allow_html=True)

                with plan_col3:
                    st.markdown("""
                        <div class='plan-card plan-premium'>
                            <h3 style='color: #a855f7;'>Premium</h3>
                            <p style='font-size: 1.8rem; font-weight: 900; color: #d8b4fe; margin: 12px 0;'>$199</p>
                            <p style='color: #888; margin-bottom: 16px;'>per month</p>
                            <ul style='text-align: left; color: #c7d2fe; font-size: 0.95rem; line-height: 1.8;'>
                                <li>✓ Real-time alerts</li>
                                <li>✓ Priority support</li>
                                <li>✓ Incident analysis</li>
                                <li>✓ IOC updates</li>
                            </ul>
                        </div>
                    """, unsafe_allow_html=True)

            if custom_iocs:
                st.markdown(f"""
                    <div class='jarvis-panel' style='background: rgba(124, 58, 237, 0.1); border-color: rgba(168, 85, 247, 0.3);'>
                        <p style='color: #d8b4fe; margin: 0;'>🎯 Using {len(custom_iocs)} custom IOC(s) for enhanced detection</p>
                    </div>
                """, unsafe_allow_html=True)

    if source_text:
        with st.expander("👁️ Preview Parsed Input", expanded=False):
            st.text_area("Parsed log preview", value=source_text, height=200, key="log_preview", disabled=True, label_visibility="collapsed")


def show_login_page() -> None:
    """Display login/registration page."""
    # Elegant login styling
    st.markdown("""
        <style>
            .login-container {
                max-width: 400px;
                margin: 60px auto;
                padding: 40px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 15px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                animation: slideInUp 0.6s ease-out;
            }
            .login-title {
                text-align: center;
                color: white;
                font-size: 32px;
                font-weight: 800;
                margin-bottom: 10px;
                letter-spacing: 2px;
            }
            .login-subtitle {
                text-align: center;
                color: rgba(255, 255, 255, 0.8);
                font-size: 14px;
                margin-bottom: 30px;
            }
            .login-input {
                width: 100%;
                padding: 12px 15px;
                margin: 10px 0;
                border: 2px solid rgba(255, 255, 255, 0.3);
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                font-size: 14px;
                backdrop-filter: blur(10px);
            }
            .login-input::placeholder {
                color: rgba(255, 255, 255, 0.6);
            }
            .login-btn {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #00d4ff 0%, #0099ff 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                margin-top: 20px;
                transition: all 0.3s ease;
            }
            .login-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 25px rgba(0, 157, 255, 0.4);
            }
            .register-link {
                text-align: center;
                color: rgba(255, 255, 255, 0.8);
                font-size: 13px;
                margin-top: 15px;
            }
            .register-link a {
                color: #00d4ff;
                text-decoration: none;
                font-weight: 600;
            }
            @keyframes slideInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        
        st.markdown('<div class="login-title">🛡️ JARVIS</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-subtitle">Cyber Threat Detection System</div>', unsafe_allow_html=True)
        
        # Login vs Register toggle
        auth_mode = st.radio("Authentication Mode", ["Login", "Register"], horizontal=True, key="auth_mode_radio", label_visibility="collapsed")
        
        if auth_mode == "Login":
            st.markdown("**Login to continue**", help="Enter your credentials")
            username = st.text_input("Username", key="login_username", placeholder="Enter username")
            password = st.text_input("Password", type="password", key="login_password", placeholder="Enter password")
            
            if st.button("🔓 Login", use_container_width=True, key="login_btn"):
                if not username or not password:
                    st.error("❌ Please enter both username and password")
                else:
                    if authenticate_user(username, password):
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.jarvis_started = False
                        st.success("✅ Login successful! Redirecting...")
                        st.rerun()
                    else:
                        st.error("❌ Invalid username or password")
        
        else:  # Register mode
            st.markdown("**Create new account**", help="Register for JARVIS")
            new_username = st.text_input("New Username", key="register_username", placeholder="Choose username")
            new_password = st.text_input("New Password", type="password", key="register_password", placeholder="Create password")
            confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm", placeholder="Confirm password")
            
            if st.button("✨ Register", use_container_width=True, key="register_btn"):
                if not new_username or not new_password:
                    st.error("❌ Please fill in all fields")
                elif new_password != confirm_password:
                    st.error("❌ Passwords do not match")
                elif len(new_password) < 6:
                    st.error("❌ Password must be at least 6 characters")
                else:
                    if register_user(new_username, new_password):
                        st.success("✅ Account created! Please login with your credentials.")
                        st.rerun()
                    else:
                        st.error("❌ Username already exists")
        
        st.markdown('</div>', unsafe_allow_html=True)


def main():
    """Main app entry point."""
    # Initialize session state
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "jarvis_started" not in st.session_state:
        st.session_state.jarvis_started = False

    # Authentication gate: show login if not authenticated
    if not st.session_state.logged_in:
        show_login_page()
    # Jarvis splash: show splash if logged in but hasn't seen it
    elif not st.session_state.jarvis_started:
        show_jarvis_splash()
    # Main dashboard: show after splash
    else:
        show_dashboard("")


if __name__ == "__main__":
    main()

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
