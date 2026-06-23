#!/usr/bin/env python3
"""
✦ Diary — v2  ·  Enhanced Edition
──────────────────────────────────────────────────────────────────────────────
Security  : SecurePassword (zeroed-on-close bytearray), AES-256-GCM canary
            integrity, DB-persisted lockout (survives restarts), restricted
            temp-file permissions (owner-only).
Stability : CryptoWorker (QThread) keeps UI responsive during bulk crypto,
            search debounce (300 ms) + session cache, WAL + foreign-key PRAGMAs,
            auto-save timer paused during crypto ops.
Usability : Undo / Redo buttons, bullet & numbered lists, Markdown/plain-text
            export, recurring scheduler tasks, inline audio player blocks,
            inline video thumbnail blocks, Alt+Up/Down entry navigation,
            Ctrl+E encrypt toggle, Ctrl+S save, full-screen startup,
            orphaned-media cleaner.
A11y      : Explicit tab order, 12 px section labels, accessible names on all
            icon-only buttons, improved contrast.
Code      : StrEnum-based Priority / TaskStatus / Recurrence, constants for
            file-extension sets.
"""

import sys, os, sqlite3, shutil, subprocess, platform, datetime
import base64, hashlib, secrets, stat, tempfile, re, json

# ── StrEnum back-compat ────────────────────────────────────────────────────────
try:
    from enum import StrEnum
except ImportError:
    from enum import Enum
    class StrEnum(str, Enum):
        pass

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtMultimedia import (QMediaPlayer, QAudioOutput, QMediaRecorder,
                                 QMediaCaptureSession, QAudioInput, QCamera,
                                 QVideoSink, QMediaFormat)
from PyQt6.QtMultimediaWidgets import QVideoWidget
from PyQt6.QtPrintSupport import QPrinter, QPrintDialog

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


# ── Constants ──────────────────────────────────────────────────────────────────
DB_NAME       = "diary.db"
MEDIA_FOLDER  = "media"
CANARY_TEXT   = "diary_master_canary_v2_ok"

AUDIO_EXTS = {".mp3", ".wav", ".ogg", ".flac", ".aac", ".m4a"}
VIDEO_EXTS = {".mp4", ".avi", ".mkv", ".mov", ".webm", ".m4v"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}

os.makedirs(MEDIA_FOLDER, exist_ok=True)


# ── Enums ──────────────────────────────────────────────────────────────────────
class Priority(StrEnum):
    LOW      = "Low"
    MEDIUM   = "Medium"
    HIGH     = "High"
    CRITICAL = "Critical"

class TaskStatus(StrEnum):
    PENDING     = "Pending"
    IN_PROGRESS = "In Progress"
    BLOCKED     = "Blocked"
    DONE        = "Done"

class Recurrence(StrEnum):
    NONE    = "none"
    DAILY   = "daily"
    WEEKLY  = "weekly"
    MONTHLY = "monthly"
    YEARLY  = "yearly"


# ── Secure password wrapper ────────────────────────────────────────────────────
class SecurePassword:
    """Stores master password in a bytearray that can be explicitly zeroed."""
    def __init__(self):
        self._data = bytearray()

    def set(self, password: str):
        self.clear()
        self._data = bytearray(password.encode("utf-8"))

    def get(self) -> str:
        return self._data.decode("utf-8") if self._data else ""

    def clear(self):
        for i in range(len(self._data)):
            self._data[i] = 0
        self._data = bytearray()

    def __bool__(self):
        return bool(self._data)

    def __del__(self):
        self.clear()


# ── Theme ──────────────────────────────────────────────────────────────────────
THEME = {
    "DARK":      "#f0f4fa",
    "PANEL":     "#e4e9f4",
    "CARD":      "#ffffff",
    "ACCENT":    "#5b4bd5",
    "ACCENT2":   "#4338ca",
    "TEXT":      "#1a1a2e",
    "MUTED":     "#4a5568",
    "GREEN":     "#15803d",
    "ORANGE":    "#b45309",
    "RED":       "#b91c1c",
    "BORDER":    "#c5cde0",
    "SCHED":     "#eaeefc",
    "ACTIONBAR": "#dde3f0",
    "TOPBAR":    "#e4e9f4",
}

def T(key): return THEME.get(key, THEME["DARK"])

def build_stylesheet():
    return f"""
QWidget {{
    background: {T('DARK')}; color: {T('TEXT')};
    font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px;
}}
QFrame#leftPanel {{ background: {T('PANEL')}; border-right: 1px solid {T('BORDER')}; }}
QFrame#schedPanel {{ background: {T('SCHED')}; border-left: 1px solid {T('BORDER')}; }}
QWidget#actionBar {{ background: {T('ACTIONBAR')}; border-top: 1px solid {T('BORDER')}; }}
QWidget#topBar {{ background: {T('TOPBAR')}; border-bottom: 1px solid {T('BORDER')}; }}
QWidget#encryptPanel {{ background: {T('CARD')}; border: 1px solid {T('BORDER')}; border-radius: 12px; }}
QPushButton {{
    background: {T('CARD')}; color: {T('TEXT')};
    border: 1px solid {T('BORDER')}; border-radius: 7px;
    padding: 6px 14px; font-weight: 500;
}}
QPushButton:hover   {{ background: {T('ACCENT')}; color: #ffffff; border-color: {T('ACCENT')}; }}
QPushButton:pressed {{ background: #3730a3; color: #ffffff; }}
QPushButton:checked {{ background: {T('ACCENT')}; color: #ffffff; }}
QPushButton#accentBtn {{
    background: {T('ACCENT')}; color: #ffffff; border: none; font-weight: 600; padding: 6px 16px;
}}
QPushButton#accentBtn:hover  {{ background: {T('ACCENT2')}; color: #ffffff; }}
QPushButton#accentBtn:pressed {{ background: #3730a3; color: #ffffff; }}
QPushButton#dangerBtn {{
    background: {T('RED')}; color: #ffffff; border: none; font-weight: 600; padding: 6px 16px;
}}
QPushButton#dangerBtn:hover {{ background: #991b1b; color: #ffffff; }}
QPushButton#successBtn {{
    background: {T('GREEN')}; color: #ffffff; border: none; font-weight: 600; padding: 6px 16px;
}}
QPushButton#successBtn:hover {{ background: #166534; color: #ffffff; }}
QPushButton#emojiBtn {{
    background: transparent; border: none; border-radius: 5px; padding: 2px;
}}
QPushButton#emojiBtn:hover {{ background: {T('BORDER')}; }}
QPushButton#fmtBtn {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')}; border-radius: 6px;
    padding: 4px 10px; font-weight: 700; color: {T('TEXT')};
}}
QPushButton#fmtBtn:hover   {{ background: {T('ACCENT')}; color: #ffffff; border-color: {T('ACCENT')}; }}
QPushButton#fmtBtn:checked {{ background: {T('ACCENT')}; color: #ffffff; border-color: {T('ACCENT')}; }}
QPushButton#schedItemBtn {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')}; border-radius: 8px;
    padding: 8px 12px; font-weight: 500; text-align: left; color: {T('TEXT')};
}}
QPushButton#schedItemBtn:hover {{ border-color: {T('ACCENT')}; }}
QPushButton#cryptoEncBtn {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #5b4bd5,stop:1 #4338ca);
    color: #ffffff; border: none; border-radius: 8px;
    font-weight: 700; padding: 8px 18px; font-size: 13px;
}}
QPushButton#cryptoEncBtn:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #4338ca,stop:1 #3730a3);
}}
QPushButton#cryptoCopyBtn {{
    background: {T('CARD')}; border: 1px solid {T('ACCENT')};
    border-radius: 8px; color: {T('ACCENT')}; font-weight: 600; padding: 6px 14px;
}}
QPushButton#cryptoCopyBtn:hover {{ background: {T('ACCENT')}; color: #ffffff; }}
QPushButton#cryptoInsertBtn {{
    background: {T('GREEN')}; color: #ffffff; border: none; border-radius: 8px;
    font-weight: 700; padding: 8px 14px;
}}
QPushButton#cryptoInsertBtn:hover {{ background: #166534; color: #ffffff; }}
QPushButton#cryptoClearBtn {{
    background: transparent; border: 1px solid {T('BORDER')};
    border-radius: 6px; color: {T('MUTED')}; padding: 5px 10px;
}}
QPushButton#cryptoClearBtn:hover {{ border-color: {T('RED')}; color: {T('RED')}; }}
QLineEdit, QSpinBox {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')};
    border-radius: 7px; padding: 6px 10px; color: {T('TEXT')};
    selection-background-color: {T('ACCENT')}; selection-color: #ffffff;
}}
QLineEdit:focus, QSpinBox:focus {{ border-color: {T('ACCENT')}; }}
QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; }}
QTextEdit {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')};
    border-radius: 10px; padding: 12px; color: {T('TEXT')};
    selection-background-color: {T('ACCENT')}; selection-color: #ffffff;
}}
QTextEdit:focus {{ border-color: {T('ACCENT')}; }}
QListWidget {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')};
    border-radius: 8px; padding: 4px; outline: none; color: {T('TEXT')};
}}
QListWidget::item {{ border-radius: 6px; padding: 7px 10px; margin: 2px 0; color: {T('TEXT')}; }}
QListWidget::item:selected {{ background: {T('ACCENT')}; color: #ffffff; }}
QListWidget::item:hover:!selected {{ background: {T('PANEL')}; color: {T('TEXT')}; }}
QCalendarWidget QWidget {{ background: {T('CARD')}; color: {T('TEXT')}; }}
QCalendarWidget QAbstractItemView {{
    background: {T('CARD')}; color: {T('TEXT')};
    selection-background-color: {T('ACCENT')}; selection-color: #ffffff;
    gridline-color: {T('BORDER')};
}}
QCalendarWidget QAbstractItemView:disabled {{ color: {T('MUTED')}; }}
QCalendarWidget QToolButton {{
    background: {T('PANEL')}; color: {T('TEXT')}; border: none;
    border-radius: 5px; padding: 4px 8px; font-weight: 600;
}}
QCalendarWidget QToolButton:hover {{ background: {T('ACCENT')}; color: #ffffff; }}
QCalendarWidget #qt_calendar_navigationbar {{
    background: {T('PANEL')}; border-bottom: 1px solid {T('BORDER')}; padding: 4px;
}}
QCalendarWidget QMenu {{ background: {T('PANEL')}; color: {T('TEXT')}; }}
QScrollBar:vertical {{ background: {T('PANEL')}; width: 8px; border-radius: 4px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {T('BORDER')}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {T('ACCENT')}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {T('PANEL')}; height: 8px; border-radius: 4px; }}
QScrollBar::handle:horizontal {{ background: {T('BORDER')}; border-radius: 4px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {T('ACCENT')}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QTabWidget::pane {{ border: none; background: transparent; }}
QTabBar::tab {{
    background: {T('CARD')}; color: {T('MUTED')}; border: 1px solid {T('BORDER')};
    border-radius: 6px; padding: 5px 12px; margin-right: 4px; font-size: 16px;
}}
QTabBar::tab:selected {{ background: {T('ACCENT')}; color: #ffffff; border-color: {T('ACCENT')}; }}
QTabBar::tab:hover:!selected {{ background: {T('PANEL')}; color: {T('TEXT')}; }}
QSlider::groove:horizontal {{ background: {T('BORDER')}; height: 4px; border-radius: 2px; }}
QSlider::handle:horizontal {{
    background: {T('ACCENT')}; width: 14px; height: 14px; margin: -5px 0; border-radius: 7px;
}}
QSlider::sub-page:horizontal {{ background: {T('ACCENT')}; border-radius: 2px; }}
QToolTip {{
    background: {T('CARD')}; color: {T('TEXT')};
    border: 1px solid {T('BORDER')}; border-radius: 5px; padding: 4px 8px;
}}
QMenu {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')};
    border-radius: 8px; padding: 4px;
}}
QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 5px; color: {T('TEXT')}; }}
QMenu::item:selected {{ background: {T('ACCENT')}; color: #ffffff; }}
QDialog {{ background: {T('DARK')}; color: {T('TEXT')}; }}
QMessageBox {{ background: {T('CARD')}; }}
QMessageBox QLabel {{ color: {T('TEXT')}; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{ color: {T('BORDER')}; }}
QDateTimeEdit {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')};
    border-radius: 7px; padding: 6px 10px; color: {T('TEXT')};
}}
QDateTimeEdit:focus {{ border-color: {T('ACCENT')}; }}
QDateTimeEdit::drop-down {{ width: 20px; }}
QComboBox {{
    background: {T('CARD')}; border: 1px solid {T('BORDER')};
    border-radius: 7px; padding: 6px 10px; color: {T('TEXT')};
}}
QComboBox:focus {{ border-color: {T('ACCENT')}; }}
QComboBox QAbstractItemView {{
    background: {T('CARD')}; color: {T('TEXT')};
    selection-background-color: {T('ACCENT')}; selection-color: #ffffff;
    border: 1px solid {T('BORDER')};
}}
QProgressBar {{
    background: {T('BORDER')}; border-radius: 3px; border: none;
    color: {T('TEXT')}; text-align: center;
}}
QProgressBar::chunk {{ background: {T('ACCENT')}; border-radius: 3px; }}
QLabel {{ color: {T('TEXT')}; background: transparent; }}
"""


# ── Widget helpers ─────────────────────────────────────────────────────────────
def open_with_system(path):
    try:
        if platform.system() == "Windows":   os.startfile(path)
        elif platform.system() == "Darwin":  subprocess.Popen(["open", path])
        else:                                subprocess.Popen(["xdg-open", path])
    except Exception as e:
        QMessageBox.warning(None, "Error", f"Could not open file:\n{e}")

def accent_btn(text, tooltip=""):
    b = QPushButton(text); b.setObjectName("accentBtn")
    b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
    if tooltip: b.setToolTip(tooltip)
    return b

def danger_btn(text, tooltip=""):
    b = QPushButton(text); b.setObjectName("dangerBtn")
    b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
    if tooltip: b.setToolTip(tooltip)
    return b

def success_btn(text, tooltip=""):
    b = QPushButton(text); b.setObjectName("successBtn")
    b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
    if tooltip: b.setToolTip(tooltip)
    return b

def fmt_btn(text, checkable=False, tooltip=""):
    b = QPushButton(text); b.setObjectName("fmtBtn"); b.setCheckable(checkable)
    b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
    if tooltip: b.setToolTip(tooltip)
    return b

def section_label(text):
    """Minimum 12 px to pass WCAG AA on small text."""
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{T('MUTED')}; font-size:12px; font-weight:700; "
        f"letter-spacing:1px; padding:8px 4px 2px 4px; background:transparent;"
    )
    return lbl

def h_sep():
    f = QFrame(); f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet(f"color:{T('BORDER')};"); return f


# ── Inline media HTML helpers ──────────────────────────────────────────────────
MASTER_PREFIX = "MENC:"
CRYPTO_PREFIX = "DENC:"

def make_audio_snippet(path: str, name: str) -> str:
    return (
        f'<a href="{path}" style="display:inline-block; text-decoration:none; '
        f'background:rgba(91,75,213,0.10); border:1.5px solid #5b4bd5; '
        f'border-radius:24px; padding:7px 18px 7px 12px; '
        f'color:#4338ca; font-weight:700; font-size:12px; margin:3px 0;">'
        f'🎵&nbsp;&nbsp;{name}&nbsp;&nbsp;▶ Play'
        f'</a><br>'
    )

def make_video_snippet(path: str, name: str) -> str:
    return (
        f'<a href="{path}" style="display:inline-block; text-decoration:none; '
        f'background:#1e1b4b; border:2px solid #5b4bd5; border-radius:12px; '
        f'padding:14px 22px; color:#e0e7ff; font-weight:700; font-size:13px; '
        f'margin:4px 0;">'
        f'🎬&nbsp;&nbsp;{name}&nbsp;&nbsp;&nbsp;▶ Play'
        f'</a><br>'
    )

def make_encrypted_snippet(token: str) -> str:
    return (
        f'<a href="{token}" '
        f'style="color:#4338ca; text-decoration:none; font-style:italic; '
        f'background:rgba(91,75,213,0.10); border-radius:5px; padding:2px 6px;">'
        f'🔒 Encrypted text&hellip; click to read'
        f'</a><br>'
    )


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════
def _derive_key(password: str, salt: bytes) -> bytes:
    if not CRYPTO_OK: raise RuntimeError("cryptography library not installed")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=260_000)
    return kdf.derive(password.encode("utf-8"))

def _hash_password(password: str, salt: bytes) -> str:
    key = _derive_key(password, salt)
    return base64.urlsafe_b64encode(salt + key).decode("ascii")

def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        raw  = base64.urlsafe_b64decode(stored_hash)
        salt = raw[:16]; expected = raw[16:]
        return secrets.compare_digest(expected, _derive_key(password, salt))
    except Exception: return False

def master_encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16); nonce = os.urandom(12)
    key  = _derive_key(password, salt)
    ct   = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{MASTER_PREFIX}{base64.urlsafe_b64encode(salt + nonce + ct).decode('ascii')}"

def master_decrypt(token: str, password: str) -> str:
    if not token.startswith(MASTER_PREFIX): raise ValueError("Not a master-encrypted token.")
    raw   = base64.urlsafe_b64decode(token[len(MASTER_PREFIX):])
    salt  = raw[:16]; nonce = raw[16:28]; ct = raw[28:]
    key   = _derive_key(password, salt)
    try:   return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except: raise ValueError("Wrong password or corrupted data.")

def master_encrypt_file(src_path: str, password: str) -> str:
    with open(src_path, "rb") as f: data = f.read()
    salt  = os.urandom(16); nonce = os.urandom(12)
    key   = _derive_key(password, salt)
    ct    = AESGCM(key).encrypt(nonce, data, None)
    enc   = src_path + ".menc"
    with open(enc, "wb") as f: f.write(salt + nonce + ct)
    return enc

def master_decrypt_file(enc_path: str, password: str, out_path: str):
    with open(enc_path, "rb") as f: raw = f.read()
    salt  = raw[:16]; nonce = raw[16:28]; ct = raw[28:]
    key   = _derive_key(password, salt)
    data  = AESGCM(key).decrypt(nonce, ct, None)
    with open(out_path, "wb") as f: f.write(data)

def crypto_encrypt(plaintext: str, password: str) -> str:
    if len(password) < 8: raise ValueError("Password must be at least 8 characters.")
    salt = os.urandom(16); nonce = os.urandom(12)
    key  = _derive_key(password, salt)
    ct   = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{CRYPTO_PREFIX}{base64.urlsafe_b64encode(salt + nonce + ct).decode('ascii')}"

def crypto_decrypt(token: str, password: str) -> str:
    if not token.startswith(CRYPTO_PREFIX): raise ValueError("Not an encrypted diary token.")
    raw   = base64.urlsafe_b64decode(token[len(CRYPTO_PREFIX):])
    salt  = raw[:16]; nonce = raw[16:28]; ct = raw[28:]
    key   = _derive_key(password, salt)
    try:   return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except: raise ValueError("Wrong password or corrupted data.")

def _encrypt_file_to(src: str, dest: str, password: str):
    with open(src, "rb") as f: data = f.read()
    salt = os.urandom(16); nonce = os.urandom(12)
    key  = _derive_key(password, salt)
    ct   = AESGCM(key).encrypt(nonce, data, None)
    with open(dest, "wb") as f: f.write(salt + nonce + ct)


# ══════════════════════════════════════════════════════════════════════════════
#  LOADING OVERLAY
# ══════════════════════════════════════════════════════════════════════════════
class LoadingOverlay(QWidget):
    def __init__(self, parent=None, message="Processing…"):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setStyleSheet("background: rgba(240,244,250,210);")

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setStyleSheet(
            f"QFrame {{ background:{T('CARD')}; border:1px solid {T('BORDER')}; border-radius:18px; }}"
        )
        card.setFixedWidth(400)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(32, 28, 32, 28); cl.setSpacing(16)

        self._lock_lbl = QLabel("🔐")
        self._lock_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lock_lbl.setStyleSheet("font-size:48px; background:transparent;")
        cl.addWidget(self._lock_lbl)

        self._msg_lbl = QLabel(message)
        self._msg_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._msg_lbl.setWordWrap(True)
        self._msg_lbl.setStyleSheet(
            f"font-size:15px; font-weight:700; color:{T('ACCENT2')}; background:transparent;"
        )
        cl.addWidget(self._msg_lbl)

        self._sub_lbl = QLabel("Please don't close the app — this may take a moment…")
        self._sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._sub_lbl.setStyleSheet(f"font-size:12px; color:{T('MUTED')}; background:transparent;")
        cl.addWidget(self._sub_lbl)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0); self._bar.setFixedHeight(6); self._bar.setTextVisible(False)
        cl.addWidget(self._bar)

        self._detail_lbl = QLabel("")
        self._detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._detail_lbl.setStyleSheet(f"font-size:11px; color:{T('MUTED')}; background:transparent;")
        cl.addWidget(self._detail_lbl)
        layout.addWidget(card)

    def set_message(self, msg: str, detail: str = ""):
        self._msg_lbl.setText(msg)
        self._detail_lbl.setText(detail)

    def set_progress(self, value: int, maximum: int):
        self._bar.setRange(0, maximum)
        self._bar.setValue(value)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.parent(): self.resize(self.parent().size())


# ══════════════════════════════════════════════════════════════════════════════
#  MASTER LOCK DB  (canary + progress_callback refactor)
# ══════════════════════════════════════════════════════════════════════════════
class MasterLockDB:
    SALT_LEN = 16

    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self._ensure_settings_table()

    def _ensure_settings_table(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY, value TEXT
            )""")
        self.db.commit()

    def _get(self, key):
        r = self.db.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return r[0] if r else None

    def _set(self, key, value):
        self.db.execute(
            "INSERT INTO app_settings (key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))
        self.db.commit()

    def _del(self, key):
        self.db.execute("DELETE FROM app_settings WHERE key=?", (key,))
        self.db.commit()

    def has_master_password(self) -> bool:
        return self._get("master_pw_hash") is not None

    def set_master_password(self, password: str):
        """Store password hash AND an encrypted canary for tamper detection."""
        salt    = os.urandom(self.SALT_LEN)
        pw_hash = _hash_password(password, salt)
        self._set("master_pw_hash", pw_hash)
        canary  = master_encrypt(CANARY_TEXT, password)
        self._set("master_canary", canary)

    def verify_master_password(self, password: str) -> bool:
        """Verify hash AND canary — detects hash-replacement attacks."""
        stored = self._get("master_pw_hash")
        if not stored: return False
        if not _verify_password(password, stored): return False
        canary = self._get("master_canary")
        if canary:
            try:   return master_decrypt(canary, password) == CANARY_TEXT
            except: return False
        return True

    def remove_master_password(self):
        self._del("master_pw_hash")
        self._del("master_canary")

    def is_locked(self) -> bool: return self.has_master_password()
    def data_is_encrypted(self) -> bool: return self._get("data_encrypted") == "1"

    # ── Bulk encrypt / decrypt ─────────────────────────────────────────────────
    def encrypt_all_data(self, password: str, progress_callback=None) -> list:
        if not CRYPTO_OK: raise RuntimeError("cryptography library required")
        def _pb(msg, detail, cur, tot):
            if progress_callback: progress_callback(msg, detail, cur, tot)

        media_errors = []
        rows  = self.db.execute("SELECT id, title, content FROM entries").fetchall()
        total = len(rows)
        try:
            for i, (eid, title, content) in enumerate(rows):
                _pb("Encrypting diary entries…", f"{i+1} / {total}", i+1, total)
                enc_t = master_encrypt(title   or "", password) if title   else ""
                enc_c = master_encrypt(content or "", password) if content else ""
                self.db.execute("UPDATE entries SET title=?,content=? WHERE id=?",
                                (enc_t, enc_c, eid))
            self.db.commit()
        except Exception:
            self.db.rollback(); raise

        media_files = [
            os.path.join(MEDIA_FOLDER, f) for f in os.listdir(MEDIA_FOLDER)
            if not f.endswith((".menc", ".part"))
        ]
        total_m = len(media_files)
        for i, fpath in enumerate(media_files):
            _pb("Encrypting media files…", f"{i+1} / {total_m}", i+1, total_m)
            tmp   = fpath + ".menc.part"
            final = fpath + ".menc"
            try:
                _encrypt_file_to(fpath, tmp, password)
                os.replace(tmp, final)
                os.remove(fpath)
            except Exception as e:
                media_errors.append((os.path.basename(fpath), str(e)))
                if os.path.exists(tmp):
                    try: os.remove(tmp)
                    except: pass

        self._set("data_encrypted", "1")
        _pb("Encryption complete!", "All data is now protected.", total, total)
        return media_errors

    def decrypt_all_data(self, password: str, progress_callback=None) -> list:
        if not CRYPTO_OK: raise RuntimeError("cryptography library required")
        def _pb(msg, detail, cur, tot):
            if progress_callback: progress_callback(msg, detail, cur, tot)

        media_errors = []
        rows  = self.db.execute("SELECT id, title, content FROM entries").fetchall()
        total = len(rows)
        try:
            for i, (eid, title, content) in enumerate(rows):
                _pb("Decrypting diary entries…", f"{i+1} / {total}", i+1, total)
                dt = master_decrypt(title, password)   if title   and title.startswith(MASTER_PREFIX)   else (title   or "")
                dc = master_decrypt(content, password) if content and content.startswith(MASTER_PREFIX) else (content or "")
                self.db.execute("UPDATE entries SET title=?,content=? WHERE id=?", (dt, dc, eid))
            self.db.commit()
        except Exception:
            self.db.rollback(); raise

        enc_files = [
            os.path.join(MEDIA_FOLDER, f) for f in os.listdir(MEDIA_FOLDER) if f.endswith(".menc")
        ]
        total_m = len(enc_files)
        for i, enc_path in enumerate(enc_files):
            _pb("Decrypting media files…", f"{i+1} / {total_m}", i+1, total_m)
            orig = enc_path[:-5]; tmp = orig + ".part"
            try:
                master_decrypt_file(enc_path, password, tmp)
                os.replace(tmp, orig)
                os.remove(enc_path)
            except Exception as e:
                media_errors.append((os.path.basename(enc_path), str(e)))
                if os.path.exists(tmp):
                    try: os.remove(tmp)
                    except: pass

        self._del("data_encrypted")
        _pb("Decryption complete!", "Master lock removed.", total_m, total_m)
        return media_errors

    def re_encrypt_all(self, old_password: str, new_password: str, progress_callback=None) -> list:
        errors  = self.decrypt_all_data(old_password, progress_callback) or []
        errors += self.encrypt_all_data(new_password, progress_callback) or []
        return errors

    def decrypt_entry_runtime(self, title: str, content: str, password: str):
        try:   t = master_decrypt(title,   password) if title   and title.startswith(MASTER_PREFIX)   else (title   or "")
        except: t = title or ""
        try:   c = master_decrypt(content, password) if content and content.startswith(MASTER_PREFIX) else (content or "")
        except: c = content or ""
        return t, c

    def decrypt_media_runtime(self, enc_path: str, password: str) -> str:
        """Decrypt .menc to a private temp dir (owner-only permissions)."""
        orig_name = os.path.basename(enc_path)[:-5]
        tmp_dir   = tempfile.mkdtemp(prefix="diary_dec_")
        os.chmod(tmp_dir, stat.S_IRWXU)           # owner only
        out_path  = os.path.join(tmp_dir, orig_name)
        master_decrypt_file(enc_path, password, out_path)
        os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR)
        return out_path


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO WORKER  (runs bulk ops in a background thread)
# ══════════════════════════════════════════════════════════════════════════════
class CryptoWorker(QThread):
    progress = pyqtSignal(str, str, int, int)   # msg, detail, current, total
    finished = pyqtSignal(list)                 # media_errors
    error    = pyqtSignal(str)

    def __init__(self, db_path: str, password: str, operation: str, old_password: str = ""):
        super().__init__()
        self.db_path      = db_path
        self.password     = password
        self.operation    = operation
        self.old_password = old_password

    def run(self):
        try:
            db = sqlite3.connect(self.db_path)
            db.execute("PRAGMA journal_mode=WAL")
            ml  = MasterLockDB(db)
            if self.operation == "encrypt":
                errors = ml.encrypt_all_data(self.password, self._report)
            elif self.operation == "decrypt":
                errors = ml.decrypt_all_data(self.password, self._report)
            elif self.operation == "reencrypt":
                errors = ml.re_encrypt_all(self.old_password, self.password, self._report)
            else:
                errors = []
            db.close()
            self.finished.emit(errors or [])
        except Exception as e:
            self.error.emit(str(e))

    def _report(self, msg, detail, cur, tot):
        self.progress.emit(msg, detail, cur, tot)


# ══════════════════════════════════════════════════════════════════════════════
#  MASTER LOGIN DIALOG  (DB-persisted lockout)
# ══════════════════════════════════════════════════════════════════════════════
DATE_FMT = "%Y-%m-%d %H:%M:%S"

class MasterLoginDialog(QDialog):
    MAX_ATTEMPTS = 5
    LOCKOUT_SECS = 30

    def __init__(self, ml_db: MasterLockDB, parent=None):
        super().__init__(parent)
        self.ml_db    = ml_db
        self._password = ""
        self._lockout_remaining = 0

        self._lockout_timer = QTimer(self)
        self._lockout_timer.setInterval(1000)
        self._lockout_timer.timeout.connect(self._tick_lockout)

        self.setWindowTitle("🔐 Diary — Locked")
        self.setMinimumWidth(420); self.resize(440, 340)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.MSWindowsFixedSizeDialogHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(16); layout.setContentsMargins(36, 36, 36, 28)

        icon = QLabel("🔐")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size:52px; background:transparent;")
        layout.addWidget(icon)

        title = QLabel("Your diary is locked")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"font-size:20px; font-weight:800; color:{T('ACCENT2')}; background:transparent;")
        layout.addWidget(title)

        sub = QLabel("Enter your master password to continue.")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(f"color:{T('MUTED')}; font-size:12px; background:transparent;")
        layout.addWidget(sub)

        pw_row = QHBoxLayout()
        self.pw_edit = QLineEdit()
        self.pw_edit.setPlaceholderText("Master password…")
        self.pw_edit.setAccessibleName("Master password")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_edit.setFixedHeight(42)
        self.pw_edit.returnPressed.connect(self._try_unlock)

        show_btn = fmt_btn("👁")
        show_btn.setAccessibleName("Show password")
        show_btn.setFixedSize(42, 42); show_btn.setCheckable(True)
        show_btn.toggled.connect(lambda v: self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
        ))
        pw_row.addWidget(self.pw_edit, stretch=1); pw_row.addWidget(show_btn)
        layout.addLayout(pw_row)

        self.err_lbl = QLabel("")
        self.err_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.err_lbl.setStyleSheet(f"color:{T('RED')}; font-size:11px; background:transparent;")
        layout.addWidget(self.err_lbl)

        self.unlock_btn = QPushButton("🔓  Unlock Diary")
        self.unlock_btn.setObjectName("cryptoEncBtn")
        self.unlock_btn.setFixedHeight(44)
        self.unlock_btn.clicked.connect(self._try_unlock)
        layout.addWidget(self.unlock_btn)

        forgot_btn = QPushButton("Forgot password? Reset all data…")
        forgot_btn.setStyleSheet(
            f"background:transparent; border:none; color:{T('RED')}; "
            f"font-size:11px; text-decoration:underline;"
        )
        forgot_btn.clicked.connect(self._forgot)
        layout.addWidget(forgot_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Restore any persisted lockout from the DB
        self._restore_lockout()

    def _restore_lockout(self):
        """If a lockout was stored in DB (app was restarted during lockout), restore it."""
        until_str = self.ml_db._get("lockout_until")
        if not until_str: return
        try:
            until = datetime.datetime.fromisoformat(until_str)
            remaining = int((until - datetime.datetime.now()).total_seconds())
            if remaining > 0:
                self._lockout_remaining = remaining
                self.pw_edit.setEnabled(False)
                self.unlock_btn.setEnabled(False)
                self.err_lbl.setText(f"⚠  Locked out. Try again in {remaining}s.")
                self._lockout_timer.start()
            else:
                self.ml_db._del("lockout_until")
                self.ml_db._del("fail_count")
        except Exception:
            pass

    def _try_unlock(self):
        if self._lockout_remaining > 0: return
        pw = self.pw_edit.text()
        if not pw:
            self.err_lbl.setText("Please enter your password."); return

        if self.ml_db.verify_master_password(pw):
            self.ml_db._del("fail_count")
            self.ml_db._del("lockout_until")
            self._password = pw
            self.accept()
        else:
            count = int(self.ml_db._get("fail_count") or "0") + 1
            self.ml_db._set("fail_count", str(count))
            self.pw_edit.clear(); self.pw_edit.setFocus()
            remaining = self.MAX_ATTEMPTS - count
            if remaining <= 0:
                until = datetime.datetime.now() + datetime.timedelta(seconds=self.LOCKOUT_SECS)
                self.ml_db._set("lockout_until", until.isoformat())
                self.ml_db._set("fail_count", "0")
                self._start_lockout()
            else:
                self.err_lbl.setText(
                    f"⚠  Incorrect password. {remaining} attempt(s) left before lockout."
                )

    def _start_lockout(self):
        self._lockout_remaining = self.LOCKOUT_SECS
        self.pw_edit.setEnabled(False); self.unlock_btn.setEnabled(False)
        self.err_lbl.setText(f"⚠  Too many attempts. Try again in {self._lockout_remaining}s.")
        self._lockout_timer.start()

    def _tick_lockout(self):
        self._lockout_remaining -= 1
        if self._lockout_remaining <= 0:
            self._lockout_timer.stop()
            self.ml_db._del("lockout_until")
            self.ml_db._del("fail_count")
            self.pw_edit.setEnabled(True); self.unlock_btn.setEnabled(True)
            self.err_lbl.setText(""); self.pw_edit.setFocus()
        else:
            self.err_lbl.setText(f"⚠  Too many attempts. Try again in {self._lockout_remaining}s.")

    def _forgot(self):
        dlg = ResetDataDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            try: self.ml_db.db.close()
            except: pass
            for p in [DB_NAME]:
                try: os.remove(p)
                except: pass
            try: shutil.rmtree(MEDIA_FOLDER)
            except: pass
            os.makedirs(MEDIA_FOLDER, exist_ok=True)
            QMessageBox.information(self, "Reset Complete", "All data erased. Restarting fresh.")
            self.reject(); QApplication.quit()

    def get_password(self) -> str: return self._password


# ══════════════════════════════════════════════════════════════════════════════
#  RESET DATA DIALOG
# ══════════════════════════════════════════════════════════════════════════════
class ResetDataDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚠ Reset All Data")
        self.setMinimumWidth(440); self.resize(460, 300)

        layout = QVBoxLayout(self)
        layout.setSpacing(14); layout.setContentsMargins(28, 24, 28, 20)

        warn = QLabel("⚠  THIS CANNOT BE UNDONE")
        warn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warn.setStyleSheet(f"font-size:16px; font-weight:800; color:{T('RED')}; background:transparent;")
        layout.addWidget(warn)

        desc = QLabel(
            "All diary entries, media files, and settings will be\n"
            "permanently deleted. There is no recovery.\n\n"
            "To confirm, type  confirm  in the box below."
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{T('TEXT')}; font-size:13px; background:transparent;")
        layout.addWidget(desc)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setPlaceholderText("Type: confirm")
        self.confirm_edit.setAccessibleName("Confirmation field — type confirm")
        self.confirm_edit.setFixedHeight(40)
        self.confirm_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.confirm_edit.textChanged.connect(self._check_confirm)
        layout.addWidget(self.confirm_edit)

        self.err_lbl = QLabel("")
        self.err_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.err_lbl.setStyleSheet(f"color:{T('RED')}; font-size:11px; background:transparent;")
        layout.addWidget(self.err_lbl)

        self.del_btn = danger_btn("🗑  Delete Everything")
        self.del_btn.setFixedHeight(40); self.del_btn.setEnabled(False)
        self._confirm_timer = QTimer(self); self._confirm_timer.setSingleShot(True)
        self._confirm_timer.timeout.connect(lambda: self.del_btn.setEnabled(True))
        self.del_btn.clicked.connect(self._confirm)

        cancel_btn = fmt_btn("Cancel"); cancel_btn.setFixedHeight(40)
        cancel_btn.clicked.connect(self.reject)

        btn_row = QHBoxLayout()
        btn_row.addWidget(cancel_btn); btn_row.addWidget(self.del_btn)
        layout.addLayout(btn_row)

    def _check_confirm(self, text):
        if text.strip().lower() == "confirm":
            self.del_btn.setEnabled(False)
            self.del_btn.setText("🗑  Wait 5s…")
            self._confirm_timer.start(5000)
            QTimer.singleShot(5000, lambda: self.del_btn.setText("🗑  Delete Everything"))
        else:
            self._confirm_timer.stop()
            self.del_btn.setEnabled(False)
            self.del_btn.setText("🗑  Delete Everything")

    def _confirm(self):
        if self.confirm_edit.text().strip().lower() == "confirm": self.accept()
        else: self.err_lbl.setText("Please type exactly: confirm")


# ══════════════════════════════════════════════════════════════════════════════
#  MASTER LOCK SETTINGS DIALOG
# ══════════════════════════════════════════════════════════════════════════════
class MasterLockDialog(QDialog):
    MIN_PASSWORD_LEN = 8

    def __init__(self, ml_db: MasterLockDB, current_name: str,
                 current_password: str, parent=None):
        super().__init__(parent)
        self.ml_db            = ml_db
        self.current_password = current_password
        self._new_name        = current_name
        self._action          = None

        self.setWindowTitle("🔐 Master Lock & Profile Settings")
        self.setMinimumWidth(500); self.resize(520, 520)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(12); layout.setContentsMargins(24, 20, 24, 20)

        hdr_row = QHBoxLayout()
        hdr_icon = QLabel("🔐"); hdr_icon.setStyleSheet("font-size:32px; background:transparent;")
        hdr_col = QVBoxLayout(); hdr_col.setSpacing(2)
        hdr_title = QLabel("Master Lock & Profile")
        hdr_title.setStyleSheet(f"font-size:16px; font-weight:800; color:{T('ACCENT2')}; background:transparent;")
        hdr_sub = QLabel("Master password encrypts ALL data (entries + media) using AES-256-GCM.")
        hdr_sub.setWordWrap(True)
        hdr_sub.setStyleSheet(f"color:{T('MUTED')}; font-size:11px; background:transparent;")
        hdr_col.addWidget(hdr_title); hdr_col.addWidget(hdr_sub)
        hdr_row.addWidget(hdr_icon); hdr_row.addSpacing(8)
        hdr_row.addLayout(hdr_col); hdr_row.addStretch()
        layout.addLayout(hdr_row); layout.addWidget(h_sep())

        layout.addWidget(section_label("PROFILE NAME"))
        name_row = QHBoxLayout()
        self.name_edit = QLineEdit(current_name)
        self.name_edit.setPlaceholderText("Your name…"); self.name_edit.setAccessibleName("Profile name")
        self.name_edit.setFixedHeight(36)
        rename_btn = accent_btn("Save Name"); rename_btn.setFixedHeight(36)
        rename_btn.clicked.connect(self._save_name)
        name_row.addWidget(self.name_edit, stretch=1); name_row.addWidget(rename_btn)
        layout.addLayout(name_row); layout.addWidget(h_sep())

        has_pw = ml_db.has_master_password()
        if has_pw:
            sl = QLabel("🔒  Master password is  SET  — data is encrypted.")
            sl.setStyleSheet(f"font-size:12px; font-weight:700; color:{T('GREEN')}; background:transparent;")
        else:
            sl = QLabel("🔓  No master password — data stored in plaintext.")
            sl.setStyleSheet(f"font-size:12px; font-weight:700; color:{T('ORANGE')}; background:transparent;")
        layout.addWidget(sl)

        if has_pw:
            layout.addWidget(section_label("CURRENT PASSWORD"))
            cr = QHBoxLayout()
            self.cur_pw_edit = QLineEdit()
            self.cur_pw_edit.setPlaceholderText("Current master password…")
            self.cur_pw_edit.setAccessibleName("Current master password")
            self.cur_pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.cur_pw_edit.setFixedHeight(36)
            if current_password: self.cur_pw_edit.setText(current_password)
            cs = fmt_btn("👁"); cs.setAccessibleName("Show current password")
            cs.setFixedSize(36, 36); cs.setCheckable(True)
            cs.toggled.connect(lambda v: self.cur_pw_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
            ))
            cr.addWidget(self.cur_pw_edit, stretch=1); cr.addWidget(cs)
            layout.addLayout(cr)
        else:
            self.cur_pw_edit = None

        layout.addWidget(section_label(f"NEW PASSWORD (min {self.MIN_PASSWORD_LEN} chars)"))
        nr = QHBoxLayout()
        self.new_pw_edit = QLineEdit()
        self.new_pw_edit.setPlaceholderText("New master password…")
        self.new_pw_edit.setAccessibleName("New master password")
        self.new_pw_edit.setEchoMode(QLineEdit.EchoMode.Password); self.new_pw_edit.setFixedHeight(36)
        ns = fmt_btn("👁"); ns.setAccessibleName("Show new password")
        ns.setFixedSize(36, 36); ns.setCheckable(True)
        ns.toggled.connect(lambda v: self.new_pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
        ))
        self.pw_strength = QProgressBar()
        self.pw_strength.setRange(0, 4); self.pw_strength.setValue(0)
        self.pw_strength.setFixedHeight(4); self.pw_strength.setTextVisible(False)
        self.new_pw_edit.textChanged.connect(self._update_strength)
        nr.addWidget(self.new_pw_edit, stretch=1); nr.addWidget(ns)
        layout.addLayout(nr); layout.addWidget(self.pw_strength)

        self.confirm_pw = QLineEdit()
        self.confirm_pw.setPlaceholderText("Confirm new password…")
        self.confirm_pw.setAccessibleName("Confirm new password")
        self.confirm_pw.setEchoMode(QLineEdit.EchoMode.Password); self.confirm_pw.setFixedHeight(36)
        layout.addWidget(self.confirm_pw)

        self.err_lbl = QLabel("")
        self.err_lbl.setStyleSheet(f"color:{T('RED')}; font-size:11px; background:transparent;")
        self.err_lbl.setWordWrap(True); layout.addWidget(self.err_lbl)

        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        if has_pw:
            ch_btn = accent_btn("🔄 Change Password"); ch_btn.setFixedHeight(38)
            ch_btn.clicked.connect(self._change_password); btn_row.addWidget(ch_btn)
            rm_btn = danger_btn("🔓 Remove Lock"); rm_btn.setFixedHeight(38)
            rm_btn.setToolTip("Decrypt everything and remove master password")
            rm_btn.clicked.connect(self._remove_password); btn_row.addWidget(rm_btn)
        else:
            set_btn = QPushButton("🔒 Set Master Password")
            set_btn.setObjectName("cryptoEncBtn"); set_btn.setFixedHeight(38)
            set_btn.clicked.connect(self._set_password); btn_row.addWidget(set_btn, stretch=1)

        close_btn = fmt_btn("Close"); close_btn.setFixedHeight(38)
        close_btn.clicked.connect(self.reject); btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        if not CRYPTO_OK:
            wl = QLabel("⚠ pip install cryptography  to enable encryption")
            wl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            wl.setStyleSheet(f"color:{T('ORANGE')}; font-size:11px; background:transparent;")
            layout.addWidget(wl)

    def _update_strength(self, text):
        s = sum([len(text) >= 8, any(c.isupper() for c in text),
                 any(c.isdigit() for c in text),
                 any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in text)])
        self.pw_strength.setValue(s)

    def _cur_password(self):
        return self.cur_pw_edit.text() if self.cur_pw_edit else ""

    def _validate_new(self):
        new = self.new_pw_edit.text(); conf = self.confirm_pw.text()
        if not new:               self.err_lbl.setText("Please enter a new password."); return None
        if len(new) < self.MIN_PASSWORD_LEN:
            self.err_lbl.setText(f"Password must be at least {self.MIN_PASSWORD_LEN} characters."); return None
        if new != conf:           self.err_lbl.setText("Passwords do not match."); return None
        if self.cur_pw_edit and new == self._cur_password():
            self.err_lbl.setText("New password must differ from current."); return None
        return new

    def _set_password(self):
        if not CRYPTO_OK: QMessageBox.warning(self, "Missing", "pip install cryptography"); return
        new = self._validate_new()
        if not new: return
        self._action = "set"; self._new_pw = new; self.accept()

    def _change_password(self):
        if not CRYPTO_OK: QMessageBox.warning(self, "Missing", "pip install cryptography"); return
        if not self.ml_db.verify_master_password(self._cur_password()):
            self.err_lbl.setText("Current password is incorrect."); return
        new = self._validate_new()
        if not new: return
        self._action = "change"; self._new_pw = new; self.accept()

    def _remove_password(self):
        if not CRYPTO_OK: QMessageBox.warning(self, "Missing", "pip install cryptography"); return
        if not self.ml_db.verify_master_password(self._cur_password()):
            self.err_lbl.setText("Current password is incorrect."); return
        if QMessageBox.question(self, "Remove Lock",
            "Decrypt ALL data and remove master password?\nAre you sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self._action = "remove"; self._new_pw = ""; self.accept()

    def _save_name(self):
        name = self.name_edit.text().strip()
        if name:
            self._new_name = name; self._action = "rename"
            QMessageBox.information(self, "Saved", f"Name updated to: {name}")
        else: self.err_lbl.setText("Name cannot be empty.")

    def get_result(self):
        return {
            "action":   self._action,
            "new_pw":   getattr(self, "_new_pw", ""),
            "cur_pw":   self._cur_password(),
            "new_name": self._new_name,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  DECRYPT DIALOG
# ══════════════════════════════════════════════════════════════════════════════
class DecryptDialog(QDialog):
    def __init__(self, token: str, parent=None):
        super().__init__(parent)
        self.token = token
        self.setWindowTitle("🔓 Decrypt Message"); self.setMinimumWidth(480); self.resize(500, 340)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(14); layout.setContentsMargins(24, 24, 24, 20)

        row = QHBoxLayout()
        lk = QLabel("🔓"); lk.setStyleSheet("font-size:36px; background:transparent;")
        col = QVBoxLayout(); col.setSpacing(2)
        tl = QLabel("Decrypt Message")
        tl.setStyleSheet(f"font-size:18px; font-weight:800; color:{T('ACCENT2')}; background:transparent;")
        sl = QLabel("Enter the password to reveal the hidden text.")
        sl.setStyleSheet(f"color:{T('MUTED')}; font-size:12px; background:transparent;")
        col.addWidget(tl); col.addWidget(sl)
        row.addWidget(lk); row.addSpacing(10); row.addLayout(col); row.addStretch()
        layout.addLayout(row); layout.addWidget(h_sep())

        pw_row = QHBoxLayout()
        self.pw_edit = QLineEdit(); self.pw_edit.setPlaceholderText("Enter password…")
        self.pw_edit.setAccessibleName("Decryption password")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password); self.pw_edit.setFixedHeight(38)
        self.pw_edit.returnPressed.connect(self._try_decrypt)
        sp = fmt_btn("👁", tooltip="Show / hide"); sp.setAccessibleName("Show password")
        sp.setFixedSize(38, 38); sp.setCheckable(True)
        sp.toggled.connect(lambda v: self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
        ))
        pw_row.addWidget(self.pw_edit, stretch=1); pw_row.addWidget(sp)
        layout.addLayout(pw_row)

        self.err_lbl = QLabel("")
        self.err_lbl.setStyleSheet(f"color:{T('RED')}; font-size:11px; background:transparent;")
        self.err_lbl.setVisible(False); layout.addWidget(self.err_lbl)

        self.out_frame = QFrame()
        self.out_frame.setStyleSheet(
            f"QFrame{{background:{T('PANEL')};border:1px solid {T('BORDER')};border-radius:10px;}}"
        )
        self.out_frame.setVisible(False)
        ol = QVBoxLayout(self.out_frame); ol.setContentsMargins(12, 10, 12, 10); ol.setSpacing(6)
        oh = QHBoxLayout()
        ot = QLabel("✅  Decrypted Text")
        ot.setStyleSheet(f"font-weight:700; color:{T('GREEN')}; font-size:12px; background:transparent;")
        self.copy_btn = QPushButton("📋 Copy"); self.copy_btn.setObjectName("cryptoCopyBtn")
        self.copy_btn.setAccessibleName("Copy decrypted text")
        self.copy_btn.setFixedHeight(28)
        oh.addWidget(ot); oh.addStretch(); oh.addWidget(self.copy_btn)
        ol.addLayout(oh)
        self.result_edit = QTextEdit(); self.result_edit.setReadOnly(True)
        self.result_edit.setFixedHeight(80); self.result_edit.setAccessibleName("Decrypted text")
        self.result_edit.setStyleSheet(
            f"background:{T('CARD')};border:1px solid {T('BORDER')};border-radius:6px;"
            f"padding:6px;color:{T('TEXT')};font-size:13px;"
        )
        ol.addWidget(self.result_edit); layout.addWidget(self.out_frame)

        br = QHBoxLayout()
        self.dec_btn = QPushButton("🔓  Decrypt")
        self.dec_btn.setObjectName("cryptoEncBtn"); self.dec_btn.setFixedHeight(38)
        self.dec_btn.clicked.connect(self._try_decrypt)
        close_btn = fmt_btn("✕  Close"); close_btn.setAccessibleName("Close dialog")
        close_btn.setFixedHeight(38); close_btn.clicked.connect(self.reject)
        br.addWidget(self.dec_btn, stretch=1); br.addWidget(close_btn)
        layout.addLayout(br)
        self.copy_btn.clicked.connect(self._copy)

    def _try_decrypt(self):
        pw = self.pw_edit.text()
        if not pw: self._show_err("Please enter the password."); return
        try:
            plain = crypto_decrypt(self.token, pw)
            self.result_edit.setPlainText(plain)
            self.out_frame.setVisible(True); self.err_lbl.setVisible(False)
            self.dec_btn.setText("🔓  Decrypted ✓"); self.dec_btn.setEnabled(False)
        except ValueError as e:
            self._show_err(str(e)); self.out_frame.setVisible(False)

    def _show_err(self, msg): self.err_lbl.setText(f"⚠  {msg}"); self.err_lbl.setVisible(True)

    def _copy(self):
        text = self.result_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.copy_btn.setText("✓ Copied!")
            QTimer.singleShot(1800, lambda: self.copy_btn.setText("📋 Copy"))


# ══════════════════════════════════════════════════════════════════════════════
#  ENCRYPT PANEL
# ══════════════════════════════════════════════════════════════════════════════
class EncryptPanel(QWidget):
    insert_requested = pyqtSignal(str)
    MIN_PW_LEN = 8

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("encryptPanel"); self.setVisible(False)
        self._token = ""
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(18); shadow.setOffset(0, 4); shadow.setColor(QColor(0, 0, 0, 30))
        self.setGraphicsEffect(shadow)

        outer = QVBoxLayout(self); outer.setContentsMargins(14, 12, 14, 14); outer.setSpacing(10)

        hdr = QHBoxLayout()
        il = QLabel("🔐"); il.setStyleSheet("font-size:20px; background:transparent;")
        ht = QVBoxLayout(); ht.setSpacing(0)
        tl = QLabel("Encrypt & Decrypt")
        tl.setStyleSheet(f"font-size:14px; font-weight:800; color:{T('ACCENT2')}; background:transparent;")
        sl = QLabel("AES-256-GCM  ·  password-protected")
        sl.setStyleSheet(f"color:{T('MUTED')}; font-size:10px; background:transparent;")
        ht.addWidget(tl); ht.addWidget(sl)
        hdr.addWidget(il); hdr.addSpacing(6); hdr.addLayout(ht); hdr.addStretch()
        if not CRYPTO_OK:
            wl = QLabel("⚠  pip install cryptography")
            wl.setStyleSheet(f"color:{T('ORANGE')}; font-size:11px; background:transparent;")
            hdr.addWidget(wl)
        cx = fmt_btn("✕"); cx.setAccessibleName("Close encrypt panel")
        cx.setFixedSize(26, 26); cx.setToolTip("Close panel")
        cx.clicked.connect(lambda: self.setVisible(False)); hdr.addWidget(cx)
        outer.addLayout(hdr); outer.addWidget(h_sep())

        body = QHBoxLayout(); body.setSpacing(12)

        # LEFT card
        lc = QFrame()
        lc.setStyleSheet(f"QFrame{{background:{T('PANEL')};border:1px solid {T('BORDER')};border-radius:10px;}}")
        ll = QVBoxLayout(lc); ll.setContentsMargins(12, 10, 12, 10); ll.setSpacing(8)
        ih = QHBoxLayout()
        it = QLabel("📝  Plain Text")
        it.setStyleSheet(f"font-weight:700; color:{T('TEXT')}; font-size:12px; background:transparent;")
        self.clear_btn = QPushButton("Clear"); self.clear_btn.setObjectName("cryptoClearBtn")
        self.clear_btn.setAccessibleName("Clear input"); self.clear_btn.setFixedHeight(24)
        ih.addWidget(it); ih.addStretch(); ih.addWidget(self.clear_btn)
        ll.addLayout(ih)
        self.plain_edit = QTextEdit()
        self.plain_edit.setPlaceholderText("Type or paste the secret text to encrypt…")
        self.plain_edit.setAccessibleName("Plain text to encrypt"); self.plain_edit.setFixedHeight(90)
        self.plain_edit.setStyleSheet(
            f"background:{T('CARD')};border:1px solid {T('BORDER')};border-radius:8px;padding:8px;color:{T('TEXT')};font-size:12px;"
        )
        ll.addWidget(self.plain_edit)
        pl = QLabel(f"🔑  Password (min {self.MIN_PW_LEN} chars)")
        pl.setStyleSheet(f"font-weight:700; color:{T('TEXT')}; font-size:11px; background:transparent;")
        ll.addWidget(pl)
        pr = QHBoxLayout(); pr.setSpacing(6)
        self.pw_edit = QLineEdit(); self.pw_edit.setPlaceholderText("Set a password…")
        self.pw_edit.setAccessibleName("Encryption password")
        self.pw_edit.setEchoMode(QLineEdit.EchoMode.Password); self.pw_edit.setFixedHeight(34)
        sp = fmt_btn("👁", tooltip="Show/hide"); sp.setAccessibleName("Show encryption password")
        sp.setFixedSize(34, 34); sp.setCheckable(True)
        sp.toggled.connect(lambda v: self.pw_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
        ))
        self._str_bar = QProgressBar(); self._str_bar.setRange(0, 4); self._str_bar.setValue(0)
        self._str_bar.setFixedHeight(4); self._str_bar.setTextVisible(False)
        self._str_bar.setStyleSheet(
            f"QProgressBar{{background:{T('BORDER')};border-radius:2px;border:none;}}"
            f"QProgressBar::chunk{{background:{T('GREEN')};border-radius:2px;}}"
        )
        self.pw_edit.textChanged.connect(self._update_strength)
        pr.addWidget(self.pw_edit, stretch=1); pr.addWidget(sp)
        ll.addLayout(pr); ll.addWidget(self._str_bar)
        self.enc_btn = QPushButton("🔒  Encrypt"); self.enc_btn.setObjectName("cryptoEncBtn")
        self.enc_btn.setAccessibleName("Encrypt text"); self.enc_btn.setFixedHeight(36)
        self.enc_btn.clicked.connect(self._do_encrypt); ll.addWidget(self.enc_btn)
        body.addWidget(lc, stretch=1)

        # RIGHT card
        rc = QFrame()
        rc.setStyleSheet(f"QFrame{{background:{T('PANEL')};border:1px solid {T('BORDER')};border-radius:10px;}}")
        rl = QVBoxLayout(rc); rl.setContentsMargins(12, 10, 12, 10); rl.setSpacing(8)
        oh = QHBoxLayout()
        ot = QLabel("🔐  Encrypted Output")
        ot.setStyleSheet(f"font-weight:700; color:{T('TEXT')}; font-size:12px; background:transparent;")
        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet(f"color:{T('GREEN')}; font-size:10px; background:transparent;")
        oh.addWidget(ot); oh.addStretch(); oh.addWidget(self.status_lbl)
        rl.addLayout(oh)
        self.enc_output = QTextEdit(); self.enc_output.setReadOnly(True)
        self.enc_output.setAccessibleName("Encrypted token output"); self.enc_output.setFixedHeight(90)
        self.enc_output.setPlaceholderText("Encrypted token will appear here…\n\nClick 🔒 Encrypt to generate.")
        self.enc_output.setStyleSheet(
            f"background:{T('CARD')};border:1px solid {T('BORDER')};border-radius:8px;padding:8px;"
            f"color:{T('MUTED')};font-size:10px;font-family:'Consolas','Courier New',monospace;"
        )
        rl.addWidget(self.enc_output)
        nl = QLabel("Remember your password — it is never stored anywhere and cannot be recovered.")
        nl.setWordWrap(True)
        nl.setStyleSheet(f"color:{T('MUTED')}; font-size:10px; background:transparent;")
        rl.addWidget(nl)
        ar = QHBoxLayout(); ar.setSpacing(6)
        self.copy_btn = QPushButton("📋  Copy Token"); self.copy_btn.setObjectName("cryptoCopyBtn")
        self.copy_btn.setAccessibleName("Copy encrypted token"); self.copy_btn.setFixedHeight(32)
        self.copy_btn.setEnabled(False)
        self.insert_btn = QPushButton("✏️  Insert into Diary"); self.insert_btn.setObjectName("cryptoInsertBtn")
        self.insert_btn.setAccessibleName("Insert encrypted snippet into diary"); self.insert_btn.setFixedHeight(32)
        self.insert_btn.setEnabled(False)
        ar.addWidget(self.copy_btn, stretch=1); ar.addWidget(self.insert_btn, stretch=1)
        rl.addLayout(ar); body.addWidget(rc, stretch=1)
        outer.addLayout(body)

        self.clear_btn.clicked.connect(self._clear_all)
        self.copy_btn.clicked.connect(self._copy_token)
        self.insert_btn.clicked.connect(self._emit_insert)

    def _update_strength(self, text):
        s = sum([len(text) >= 8, any(c.isupper() for c in text),
                 any(c.isdigit() for c in text),
                 any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in text)])
        self._str_bar.setValue(s)
        colors = ["#b91c1c","#b45309","#ca8a04","#15803d"]
        color = colors[min(s-1, 3)] if s > 0 else "#b91c1c"
        self._str_bar.setStyleSheet(
            f"QProgressBar{{background:{T('BORDER')};border-radius:2px;border:none;}}"
            f"QProgressBar::chunk{{background:{color};border-radius:2px;}}"
        )

    def _do_encrypt(self):
        if not CRYPTO_OK:
            QMessageBox.warning(self, "Missing Library",
                "pip install cryptography\n\nThen restart the app."); return
        plain = self.plain_edit.toPlainText().strip()
        pw    = self.pw_edit.text()
        if not plain: self._flash("Please enter some text to encrypt."); return
        if not pw:    self._flash("Please set a password."); return
        if len(pw) < self.MIN_PW_LEN: self._flash(f"Password must be at least {self.MIN_PW_LEN} chars."); return
        try:
            self._token = crypto_encrypt(plain, pw)
            self.enc_output.setPlainText(self._token)
            self.enc_output.setStyleSheet(
                f"background:{T('CARD')};border:1px solid {T('ACCENT')};border-radius:8px;padding:8px;"
                f"color:{T('ACCENT2')};font-size:10px;font-family:'Consolas','Courier New',monospace;"
            )
            self.status_lbl.setText("✓ Encrypted!")
            self.copy_btn.setEnabled(True); self.insert_btn.setEnabled(True)
            self.enc_btn.setText("🔒  Re-encrypt")
        except Exception as e: self._flash(f"Encryption failed: {e}")

    def _flash(self, msg):
        self.status_lbl.setStyleSheet(f"color:{T('RED')}; font-size:10px; background:transparent;")
        self.status_lbl.setText(f"⚠ {msg}")
        QTimer.singleShot(3000, lambda: (
            self.status_lbl.setText(""),
            self.status_lbl.setStyleSheet(f"color:{T('GREEN')}; font-size:10px; background:transparent;")
        ))

    def _clear_all(self):
        self.plain_edit.clear(); self.pw_edit.clear(); self.enc_output.clear()
        self._token = ""; self.status_lbl.setText("")
        self.copy_btn.setEnabled(False); self.insert_btn.setEnabled(False)
        self.enc_btn.setText("🔒  Encrypt")

    def _copy_token(self):
        if self._token:
            QApplication.clipboard().setText(self._token)
            self.copy_btn.setText("✓  Copied!")
            QTimer.singleShot(1800, lambda: self.copy_btn.setText("📋  Copy Token"))

    def _emit_insert(self):
        if self._token: self.insert_requested.emit(self._token)


# ══════════════════════════════════════════════════════════════════════════════
#  IMAGE VIEWER
# ══════════════════════════════════════════════════════════════════════════════
class ImageViewer(QDialog):
    delete_requested = pyqtSignal(str)

    def __init__(self, path, parent=None, diary_path=None):
        super().__init__(parent)
        self.setWindowTitle("Image Viewer")
        self.setMinimumSize(500, 400); self.resize(960, 680)
        self.path = path; self.diary_path = diary_path or path
        self.scale = 1.0; self._temp_path = (path != self.diary_path)

        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)

        tb = QWidget()
        tb.setStyleSheet(f"background:{T('PANEL')};border-bottom:1px solid {T('BORDER')};")
        tl = QHBoxLayout(tb); tl.setContentsMargins(10,6,10,6); tl.setSpacing(6)

        zi = fmt_btn("🔍+", tooltip="Zoom In"); zi.setAccessibleName("Zoom in")
        zo = fmt_btn("🔍−", tooltip="Zoom Out"); zo.setAccessibleName("Zoom out")
        ft = fmt_btn("⊡ Fit", tooltip="Fit to window"); ft.setAccessibleName("Fit image")
        oo = fmt_btn("1:1", tooltip="Original size"); oo.setAccessibleName("Original size")
        sy = fmt_btn("↗ Open in System Viewer"); sy.setAccessibleName("Open in system viewer")
        self.del_btn = danger_btn("🗑 Delete")
        self.del_btn.setFixedHeight(28); self.del_btn.setToolTip("Remove media from diary")
        nl = QLabel(f"  {os.path.basename(self.diary_path)}")
        nl.setStyleSheet(f"color:{T('MUTED')}; font-size:12px; background:transparent;")

        for w in [zi, zo, ft, oo, sy]: tl.addWidget(w)
        tl.addStretch(); tl.addWidget(self.del_btn); tl.addWidget(nl)
        layout.addWidget(tb)

        self.scroll = QScrollArea(); self.scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll.setWidgetResizable(False)
        self.scroll.setStyleSheet(f"background:{T('DARK')};border:none;")
        self.img_label = QLabel(); self.img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll.setWidget(self.img_label); layout.addWidget(self.scroll)

        self.pixmap = QPixmap(path); self._fit_to_window()
        zi.clicked.connect(lambda: self._zoom(1.25)); zo.clicked.connect(lambda: self._zoom(0.8))
        ft.clicked.connect(self._fit_to_window); oo.clicked.connect(self._original_size)
        sy.clicked.connect(lambda: open_with_system(path))
        self.del_btn.clicked.connect(self._delete_media)

    def _delete_media(self):
        if QMessageBox.question(self, "Delete Media",
            f"Delete {os.path.basename(self.diary_path)} permanently?\n"
            "This will also remove it from your diary entries.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.delete_requested.emit(self.diary_path); self.close()

    def _fit_to_window(self):
        avail = self.scroll.viewport().size() - QSize(4, 4)
        s = self.pixmap.scaled(avail, Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation)
        self.img_label.setPixmap(s); self.img_label.resize(s.size())
        self.scale = s.width() / max(self.pixmap.width(), 1)

    def _original_size(self):
        self.scale = 1.0; self.img_label.setPixmap(self.pixmap)
        self.img_label.resize(self.pixmap.size())

    def _zoom(self, f):
        self.scale = max(0.05, min(self.scale * f, 20.0))
        s = self.pixmap.scaled(int(self.pixmap.width() * self.scale),
                               int(self.pixmap.height() * self.scale),
                               Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation)
        self.img_label.setPixmap(s); self.img_label.resize(s.size())

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.scale < 1.01: self._fit_to_window()

    def keyPressEvent(self, e):
        k = e.key()
        if   k == Qt.Key.Key_Escape:                    self.close()
        elif k in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):  self._zoom(1.25)
        elif k == Qt.Key.Key_Minus:                      self._zoom(0.8)
        elif k == Qt.Key.Key_0:                          self._fit_to_window()

    def closeEvent(self, e):
        if self._temp_path and os.path.exists(self.path) and self.path != self.diary_path:
            try:
                os.remove(self.path)
                shutil.rmtree(os.path.dirname(self.path), ignore_errors=True)
            except: pass
        super().closeEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
#  MEDIA PLAYER
# ══════════════════════════════════════════════════════════════════════════════
class MediaPlayer(QDialog):
    delete_requested = pyqtSignal(str)

    def __init__(self, path, parent=None, diary_path=None):
        super().__init__(parent)
        self.diary_path   = diary_path or path
        self._temp_path   = (path != self.diary_path)
        self._actual_path = path
        self.setWindowTitle(f"▶  {os.path.basename(self.diary_path)}")
        self.resize(860, 560)
        self.is_video = os.path.splitext(path)[1].lower() in VIDEO_EXTS

        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(14,14,14,14)

        if self.is_video:
            self.video_widget = QVideoWidget()
            self.video_widget.setMinimumHeight(380)
            self.video_widget.setStyleSheet("background:#000; border-radius:10px;")
            layout.addWidget(self.video_widget)
        else:
            bn = QLabel("🎵"); bn.setAlignment(Qt.AlignmentFlag.AlignCenter)
            bn.setStyleSheet(
                f"font-size:72px; background:{T('CARD')}; border-radius:12px; "
                f"padding:40px; color:{T('ACCENT')};"
            )
            nl = QLabel(os.path.basename(self.diary_path)); nl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            nl.setStyleSheet(f"font-size:15px; color:{T('MUTED')}; padding-bottom:8px; background:transparent;")
            layout.addWidget(bn); layout.addWidget(nl)

        self.seek_slider = QSlider(Qt.Orientation.Horizontal)
        self.seek_slider.setAccessibleName("Playback position"); self.seek_slider.setRange(0, 0)
        self.seek_slider.sliderMoved.connect(lambda p: self.player.setPosition(p))
        layout.addWidget(self.seek_slider)

        tr = QHBoxLayout()
        self.time_cur = QLabel("0:00"); self.time_tot = QLabel("0:00")
        for l in [self.time_cur, self.time_tot]:
            l.setStyleSheet(f"color:{T('MUTED')}; font-size:12px; background:transparent;")
        tr.addWidget(self.time_cur); tr.addStretch(); tr.addWidget(self.time_tot)
        layout.addLayout(tr)

        cr = QHBoxLayout(); cr.setSpacing(8)
        self.play_btn  = accent_btn("▶ Play"); self.play_btn.setAccessibleName("Play")
        self.pause_btn = fmt_btn("⏸ Pause"); self.pause_btn.setAccessibleName("Pause")
        self.stop_btn  = fmt_btn("⏹ Stop");  self.stop_btn.setAccessibleName("Stop")
        self.mute_btn  = fmt_btn("🔊", checkable=True, tooltip="Toggle Mute")
        self.mute_btn.setAccessibleName("Mute")
        self.vol_slider = QSlider(Qt.Orientation.Horizontal)
        self.vol_slider.setAccessibleName("Volume"); self.vol_slider.setRange(0, 100)
        self.vol_slider.setValue(80); self.vol_slider.setFixedWidth(110)
        sys_btn  = fmt_btn("↗ System Player"); sys_btn.setAccessibleName("Open in system player")
        self.del_btn = danger_btn("🗑 Delete"); self.del_btn.setAccessibleName("Delete media file")
        for w in [self.play_btn, self.pause_btn, self.stop_btn,
                  self.mute_btn, self.vol_slider, sys_btn, self.del_btn]:
            cr.addWidget(w)
        cr.addStretch(); layout.addLayout(cr)

        self.player = QMediaPlayer(); self.audio_out = QAudioOutput()
        self.audio_out.setVolume(0.8); self.player.setAudioOutput(self.audio_out)
        if self.is_video: self.player.setVideoOutput(self.video_widget)
        self.player.setSource(QUrl.fromLocalFile(os.path.abspath(path)))

        self.play_btn.clicked.connect(self.player.play)
        self.pause_btn.clicked.connect(self.player.pause)
        self.stop_btn.clicked.connect(self.player.stop)
        self.mute_btn.toggled.connect(self._toggle_mute)
        self.vol_slider.valueChanged.connect(lambda v: self.audio_out.setVolume(v / 100))
        sys_btn.clicked.connect(lambda: open_with_system(path))
        self.del_btn.clicked.connect(self._delete_media)
        self.player.durationChanged.connect(lambda ms: (
            self.seek_slider.setRange(0, ms), self.time_tot.setText(self._fmt(ms))
        ))
        self.player.positionChanged.connect(self._on_position)
        self.player.errorOccurred.connect(
            lambda err, msg: QMessageBox.warning(self, "Playback Error", msg) if err != QMediaPlayer.Error.NoError else None
        )
        self.player.play()

    def _delete_media(self):
        if QMessageBox.question(self, "Delete Media",
            f"Delete {os.path.basename(self.diary_path)} permanently?\n"
            "This will also remove it from your diary entries.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.player.stop(); self.delete_requested.emit(self.diary_path); self.close()

    def _toggle_mute(self, m):
        self.audio_out.setMuted(m); self.mute_btn.setText("🔇" if m else "🔊")

    def _on_position(self, ms):
        self.seek_slider.blockSignals(True); self.seek_slider.setValue(ms)
        self.seek_slider.blockSignals(False); self.time_cur.setText(self._fmt(ms))

    def _fmt(self, ms): s = ms // 1000; return f"{s // 60}:{s % 60:02d}"

    def closeEvent(self, e):
        self.player.stop(); self.player.setSource(QUrl()); super().closeEvent(e)
        if self._temp_path and os.path.exists(self._actual_path):
            try:
                os.remove(self._actual_path)
                shutil.rmtree(os.path.dirname(self._actual_path), ignore_errors=True)
            except: pass

    def keyPressEvent(self, e):
        k = e.key()
        if k == Qt.Key.Key_Space:
            if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState: self.player.pause()
            else: self.player.play()
        elif k == Qt.Key.Key_Escape: self.close()
        elif k == Qt.Key.Key_M: self.mute_btn.setChecked(not self.mute_btn.isChecked())


# ══════════════════════════════════════════════════════════════════════════════
#  RECORDER
# ══════════════════════════════════════════════════════════════════════════════
class RecorderDialog(QDialog):
    file_saved = pyqtSignal(str)

    def __init__(self, with_video=False, parent=None):
        super().__init__(parent)
        self.with_video  = with_video; self.output_path = ""
        self._camera_started = False
        self.setWindowTitle("🎙 Voice Recorder" if not with_video else "🎥 Video Recorder")
        self.resize(520, 420 if with_video else 260)

        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(16,16,16,16)

        if with_video:
            self.viewfinder = QVideoWidget(); self.viewfinder.setMinimumHeight(260)
            self.viewfinder.setStyleSheet("background:#000; border-radius:10px;")
            layout.addWidget(self.viewfinder)

        self.timer_label = QLabel("00:00"); self.timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.timer_label.setStyleSheet(
            f"font-size:32px; font-weight:700; color:{T('ACCENT2')}; background:transparent;"
        )
        layout.addWidget(self.timer_label)

        self.level_bar = QProgressBar(); self.level_bar.setRange(0, 100)
        self.level_bar.setValue(0); self.level_bar.setTextVisible(False)
        self.level_bar.setFixedHeight(6); layout.addWidget(self.level_bar)

        self.status_lbl = QLabel("Ready — press Record to start")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setStyleSheet(f"color:{T('MUTED')}; background:transparent;")
        layout.addWidget(self.status_lbl)

        br = QHBoxLayout(); br.setSpacing(8)
        self.rec_btn   = accent_btn("⏺ Record"); self.rec_btn.setAccessibleName("Start recording")
        self.pause_btn = fmt_btn("⏸ Pause");     self.pause_btn.setAccessibleName("Pause recording")
        self.stop_btn  = fmt_btn("⏹ Stop");      self.stop_btn.setAccessibleName("Stop recording")
        cancel_btn     = fmt_btn("✕ Cancel");    cancel_btn.setAccessibleName("Cancel recording")
        self.pause_btn.setEnabled(False); self.stop_btn.setEnabled(False)
        for b in [self.rec_btn, self.pause_btn, self.stop_btn, cancel_btn]: br.addWidget(b)
        layout.addLayout(br)

        self.session     = QMediaCaptureSession(); self.recorder = QMediaRecorder()
        self.session.setRecorder(self.recorder)
        self.audio_input = QAudioInput(); self.session.setAudioInput(self.audio_input)
        if with_video:
            self.camera = QCamera(); self.session.setCamera(self.camera)
            self.session.setVideoOutput(self.viewfinder)
            self.camera.start(); self._camera_started = True

        self._elapsed = QTimer(); self._elapsed.setInterval(1000); self._elapsed.timeout.connect(self._tick)
        self._seconds = 0; self._paused = False
        self._level_timer = QTimer(); self._level_timer.setInterval(150)
        self._level_timer.timeout.connect(self._update_level)

        self.rec_btn.clicked.connect(self._start); self.pause_btn.clicked.connect(self._toggle_pause)
        self.stop_btn.clicked.connect(lambda: self.recorder.stop())
        cancel_btn.clicked.connect(self._cancel)
        self.recorder.recorderStateChanged.connect(self._state_changed)
        self.recorder.errorOccurred.connect(
            lambda err, msg: QMessageBox.warning(self, "Recorder Error", msg)
        )

    def _update_level(self):
        import random
        self.level_bar.setValue(0 if self._paused else random.randint(20, 90))

    def _start(self):
        ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "mp4" if self.with_video else "wav"
        name = f"{'video' if self.with_video else 'voice'}_{ts}.{ext}"
        self.output_path = os.path.abspath(os.path.join(MEDIA_FOLDER, name))
        fmt = QMediaFormat()
        fmt.setFileFormat(QMediaFormat.FileFormat.MPEG4 if self.with_video else QMediaFormat.FileFormat.Wave)
        self.recorder.setMediaFormat(fmt)
        self.recorder.setOutputLocation(QUrl.fromLocalFile(self.output_path))
        self.recorder.record()

    def _toggle_pause(self):
        if self._paused:
            self.recorder.record(); self._paused = False; self._elapsed.start()
            self.pause_btn.setText("⏸ Pause")
            self.status_lbl.setText("● Recording…")
            self.status_lbl.setStyleSheet(f"color:{T('RED')}; font-weight:700; background:transparent;")
        else:
            self.recorder.pause(); self._paused = True; self._elapsed.stop()
            self.pause_btn.setText("▶ Resume")
            self.status_lbl.setText("⏸ Paused")
            self.status_lbl.setStyleSheet(f"color:{T('ORANGE')}; font-weight:700; background:transparent;")

    def _cancel(self):
        self._stop_all()
        if self.output_path and os.path.exists(self.output_path):
            try: os.remove(self.output_path)
            except: pass
        self.reject()

    def _stop_all(self):
        try: self._elapsed.stop(); self._level_timer.stop()
        except: pass
        try:
            if self.recorder.recorderState() != QMediaRecorder.RecorderState.StoppedState:
                self.recorder.stop()
        except: pass
        try:
            if self.with_video and self._camera_started:
                self.camera.stop(); self._camera_started = False
        except: pass
        try: self.session.setAudioInput(None)
        except: pass

    def _state_changed(self, state):
        if state == QMediaRecorder.RecorderState.RecordingState:
            if not self._paused: self._seconds = 0
            self._elapsed.start(); self._level_timer.start(); self._paused = False
            self.rec_btn.setEnabled(False); self.pause_btn.setEnabled(True); self.stop_btn.setEnabled(True)
            self.status_lbl.setText("● Recording…")
            self.status_lbl.setStyleSheet(f"color:{T('RED')}; font-weight:700; background:transparent;")
        elif state == QMediaRecorder.RecorderState.StoppedState:
            self._elapsed.stop(); self._level_timer.stop(); self.level_bar.setValue(0)
            self.rec_btn.setEnabled(True); self.pause_btn.setEnabled(False); self.stop_btn.setEnabled(False)
            self.pause_btn.setText("⏸ Pause"); self._paused = False
            self.status_lbl.setText(f"✓ Saved → {os.path.basename(self.output_path)}")
            self.status_lbl.setStyleSheet(f"color:{T('GREEN')}; background:transparent;")
            if self.output_path and os.path.exists(self.output_path):
                self._stop_all(); self.file_saved.emit(self.output_path); self.accept()

    def _tick(self):
        self._seconds += 1; m, s = divmod(self._seconds, 60)
        self.timer_label.setText(f"{m:02d}:{s:02d}")

    def closeEvent(self, e): self._stop_all(); super().closeEvent(e)
    def reject(self):        self._stop_all(); super().reject()


# ══════════════════════════════════════════════════════════════════════════════
#  EMOJI BAR
# ══════════════════════════════════════════════════════════════════════════════
EMOJI_ROWS = [
    ["😀","😂","😍","🥰","😎","🤔","😢","😡","🥳","😴","🤯","🙄","😇","🤩","😬","🫡","😋","🤗"],
    ["👍","👎","👏","🙏","🤝","✌️","🫶","💪","🤞","👋","🫂","❤️","💔","🔥","⭐","✨","💯","🎉"],
    ["🌸","🌿","☀️","🌙","🌈","🍕","🍔","☕","🍷","🎂","🐶","🐱","🦋","🌺","🍀","🎵","🌊","🦄"],
    ["📝","📚","💡","🔑","🎯","🏆","💰","📱","💻","🎮","🚀","✈️","🏠","🎁","💎","⚡","🔮","🎨"],
]

class EmojiBar(QWidget):
    emoji_clicked = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent); self.setMaximumHeight(70)
        layout = QVBoxLayout(self); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)
        self.tabs = QTabWidget(); self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        for name, row in zip(["😀","👍","🌸","📝"], EMOJI_ROWS):
            scroll = QScrollArea()
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setWidgetResizable(True); scroll.setFixedHeight(36)
            scroll.setStyleSheet("border:none; background:transparent;")
            container = QWidget(); container.setStyleSheet("background:transparent;")
            h = QHBoxLayout(container); h.setContentsMargins(4,2,4,2); h.setSpacing(2)
            for emoji in row:
                btn = QPushButton(emoji); btn.setObjectName("emojiBtn")
                btn.setFixedSize(28, 28); btn.setFont(QFont("Segoe UI Emoji", 14))
                btn.setToolTip(emoji); btn.setAccessibleName(f"Insert emoji {emoji}")
                btn.clicked.connect(lambda _, em=emoji: self.emoji_clicked.emit(em))
                h.addWidget(btn)
            h.addStretch(); scroll.setWidget(container); self.tabs.addTab(scroll, name)
        layout.addWidget(self.tabs)


# ══════════════════════════════════════════════════════════════════════════════
#  DIARY EDITOR
# ══════════════════════════════════════════════════════════════════════════════
class DiaryEditor(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent); self.setAcceptRichText(True); self.setAcceptDrops(True)
        self.setAccessibleName("Diary entry text"); self.setPlaceholderText("Start writing your thoughts…")

    def mousePressEvent(self, e):
        cursor = self.cursorForPosition(e.pos()); fmt = cursor.charFormat()
        if fmt.isAnchor():
            url = fmt.anchorHref(); p = self.parent()
            while p and not isinstance(p, DiaryApp): p = p.parent()
            if p: p.handle_link(url)
            return
        super().mousePressEvent(e)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls(): e.acceptProposedAction()

    def dropEvent(self, e):
        for url in e.mimeData().urls():
            path = url.toLocalFile()
            if path:
                p = self.parent()
                while p and not isinstance(p, DiaryApp): p = p.parent()
                if p: p.insert_file(path)


# ══════════════════════════════════════════════════════════════════════════════
#  STATUS BAR
# ══════════════════════════════════════════════════════════════════════════════
class StatusBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self.setFixedHeight(28)
        self.setStyleSheet(f"background:{T('PANEL')}; border-top:1px solid {T('BORDER')};")
        layout = QHBoxLayout(self); layout.setContentsMargins(12, 0, 12, 0)
        self.word_label  = QLabel("Words: 0"); self.char_label = QLabel("Chars: 0")
        self.saved_label = QLabel("● Saved"); self.lock_label = QLabel("")
        for l in [self.word_label, self.char_label]:
            l.setStyleSheet(f"color:{T('MUTED')}; font-size:11px; background:transparent;")
        self.saved_label.setStyleSheet(f"color:{T('GREEN')}; font-size:11px; background:transparent;")
        self.lock_label.setStyleSheet(f"color:{T('ACCENT')}; font-size:11px; background:transparent;")
        sep = QLabel("·"); sep.setStyleSheet(f"color:{T('BORDER')}; background:transparent;")
        layout.addWidget(self.word_label); layout.addWidget(sep)
        layout.addWidget(self.char_label); layout.addStretch()
        layout.addWidget(self.lock_label); layout.addWidget(self.saved_label)

    def update_counts(self, text):
        w = len(text.split()) if text.strip() else 0
        self.word_label.setText(f"Words: {w}"); self.char_label.setText(f"Chars: {len(text)}")

    def set_saved(self, saved: bool):
        if saved:
            self.saved_label.setText("● Saved")
            self.saved_label.setStyleSheet(f"color:{T('GREEN')}; font-size:11px; background:transparent;")
        else:
            self.saved_label.setText("● Unsaved")
            self.saved_label.setStyleSheet(f"color:{T('ORANGE')}; font-size:11px; background:transparent;")

    def set_lock_status(self, locked: bool):
        self.lock_label.setText("🔒 Encrypted  ·" if locked else "")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY CARD
# ══════════════════════════════════════════════════════════════════════════════
class EntryCard(QFrame):
    open_requested = pyqtSignal(int)

    def __init__(self, eid, date, title, preview, parent=None):
        super().__init__(parent); self.eid = eid
        self.setStyleSheet(
            f"QFrame{{background:{T('CARD')};border:1px solid {T('BORDER')};border-radius:10px;padding:0;}}"
            f"QFrame:hover{{border-color:{T('ACCENT')};}}"
        )
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        layout = QVBoxLayout(self); layout.setContentsMargins(14,10,14,10); layout.setSpacing(4)
        hdr = QHBoxLayout()
        dl = QLabel(f"📅 {date}"); dl.setStyleSheet(f"color:{T('MUTED')}; font-size:11px; background:transparent;")
        ob = QPushButton("✏️ Open & Edit"); ob.setObjectName("fmtBtn")
        ob.setAccessibleName(f"Open diary entry from {date}")
        ob.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        ob.clicked.connect(lambda: self.open_requested.emit(self.eid))
        hdr.addWidget(dl); hdr.addStretch(); hdr.addWidget(ob)
        layout.addLayout(hdr)
        tl = QLabel(title or "Untitled")
        tl.setStyleSheet(f"font-size:14px; font-weight:700; color:{T('ACCENT2')}; background:transparent;")
        layout.addWidget(tl)
        pl = QLabel(preview); pl.setWordWrap(True)
        pl.setStyleSheet(f"color:{T('MUTED')}; font-size:12px; background:transparent;")
        layout.addWidget(pl)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton: self.open_requested.emit(self.eid)
        super().mousePressEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
#  SCHEDULER DB  (with recurrence support)
# ══════════════════════════════════════════════════════════════════════════════
PRIORITY_COLORS = {
    Priority.LOW: "#15803d", Priority.MEDIUM: "#b45309",
    Priority.HIGH: "#b91c1c", Priority.CRITICAL: "#7e22ce",
}
STATUS_ICONS = {
    TaskStatus.PENDING: "🕐", TaskStatus.IN_PROGRESS: "⚡",
    TaskStatus.BLOCKED: "🚫", TaskStatus.DONE: "✅",
}

class SchedulerDB:
    def __init__(self, db: sqlite3.Connection):
        self.db = db; self._create()

    def _create(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS scheduler_tasks (
                id             INTEGER PRIMARY KEY,
                action         TEXT    NOT NULL,
                created_at     TEXT    NOT NULL,
                due_date       TEXT    NOT NULL,
                priority       TEXT    DEFAULT 'Medium',
                current_status TEXT    DEFAULT 'Pending',
                completed      INTEGER DEFAULT 0,
                completed_at   TEXT,
                recurrence     TEXT    DEFAULT 'none'
            );
            CREATE TABLE IF NOT EXISTS scheduler_logs (
                id        INTEGER PRIMARY KEY,
                task_id   INTEGER NOT NULL,
                logged_at TEXT    NOT NULL,
                status    TEXT    NOT NULL,
                note      TEXT,
                FOREIGN KEY(task_id) REFERENCES scheduler_tasks(id)
            );
        """)
        # Migration: add recurrence to older DBs
        try:
            self.db.execute("ALTER TABLE scheduler_tasks ADD COLUMN recurrence TEXT DEFAULT 'none'")
            self.db.commit()
        except sqlite3.OperationalError:
            pass

    def add_task(self, action, due_date, priority=Priority.MEDIUM, recurrence=Recurrence.NONE):
        now = datetime.datetime.now().strftime(DATE_FMT)
        cur = self.db.execute(
            "INSERT INTO scheduler_tasks (action,created_at,due_date,priority,recurrence) VALUES(?,?,?,?,?)",
            (action, now, due_date, str(priority), str(recurrence)),
        )
        self.db.commit(); tid = cur.lastrowid
        self.add_log(tid, TaskStatus.PENDING, "Task created")
        return tid

    def all_tasks(self, show_completed=False):
        q = "SELECT * FROM scheduler_tasks"
        if not show_completed: q += " WHERE completed=0"
        return self.db.execute(q + " ORDER BY due_date ASC").fetchall()

    def get_task(self, tid):
        return self.db.execute("SELECT * FROM scheduler_tasks WHERE id=?", (tid,)).fetchone()

    def update_status(self, tid, status):
        self.db.execute("UPDATE scheduler_tasks SET current_status=? WHERE id=?", (status, tid))
        self.db.commit(); self.add_log(tid, status)

    def mark_complete(self, tid):
        now  = datetime.datetime.now().strftime(DATE_FMT)
        task = self.get_task(tid)
        self.db.execute(
            "UPDATE scheduler_tasks SET completed=1,current_status='Done',completed_at=? WHERE id=?",
            (now, tid))
        self.db.commit(); self.add_log(tid, TaskStatus.DONE, "Marked as complete")

        # Auto-create next occurrence
        recurrence = task[8] if len(task) > 8 else Recurrence.NONE
        if recurrence and recurrence != Recurrence.NONE:
            due_dt = _safe_parse_dt(task[3])
            if due_dt:
                try:
                    if recurrence == Recurrence.DAILY:
                        next_due = due_dt + datetime.timedelta(days=1)
                    elif recurrence == Recurrence.WEEKLY:
                        next_due = due_dt + datetime.timedelta(weeks=1)
                    elif recurrence == Recurrence.MONTHLY:
                        m = due_dt.month % 12 + 1
                        y = due_dt.year + (due_dt.month // 12)
                        try:   next_due = due_dt.replace(year=y, month=m)
                        except ValueError: next_due = datetime.datetime(y, m, 1)
                    elif recurrence == Recurrence.YEARLY:
                        next_due = due_dt.replace(year=due_dt.year + 1)
                    else: return
                    self.add_task(task[1], next_due.strftime(DATE_FMT), task[4], recurrence)
                except Exception: pass

    def delete_task(self, tid):
        self.db.execute("DELETE FROM scheduler_logs  WHERE task_id=?", (tid,))
        self.db.execute("DELETE FROM scheduler_tasks WHERE id=?",      (tid,))
        self.db.commit()

    def active_due_dates(self):
        return [r[0] for r in self.db.execute(
            "SELECT DISTINCT due_date FROM scheduler_tasks WHERE completed=0"
        ).fetchall()]

    def add_log(self, task_id, status, note=""):
        now = datetime.datetime.now().strftime(DATE_FMT)
        self.db.execute(
            "INSERT INTO scheduler_logs (task_id,logged_at,status,note) VALUES(?,?,?,?)",
            (task_id, now, str(status), note)); self.db.commit()

    def logs_for(self, task_id):
        return self.db.execute(
            "SELECT logged_at,status,note FROM scheduler_logs WHERE task_id=? ORDER BY id DESC",
            (task_id,)).fetchall()


def _safe_parse_dt(text):
    try:    return datetime.datetime.strptime(text, DATE_FMT)
    except: return None


# ── New Task Dialog ────────────────────────────────────────────────────────────
class NewTaskDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("➕ New Scheduled Task"); self.setMinimumWidth(460); self.resize(480, 330)
        layout = QFormLayout(self); layout.setSpacing(12); layout.setContentsMargins(20,20,20,20)

        self.action_edit = QLineEdit()
        self.action_edit.setPlaceholderText("Describe the action / task…")
        self.action_edit.setAccessibleName("Task description")
        layout.addRow("Action *", self.action_edit)

        self.due_dt = QDateTimeEdit(QDateTime.currentDateTime().addDays(1))
        self.due_dt.setDisplayFormat("yyyy-MM-dd  HH:mm"); self.due_dt.setCalendarPopup(True)
        self.due_dt.setMinimumDateTime(QDateTime.currentDateTime())
        self.due_dt.setAccessibleName("Due date and time")
        layout.addRow("Due date / time *", self.due_dt)

        self.priority_combo = QComboBox()
        self.priority_combo.addItems([p.value for p in Priority])
        self.priority_combo.setCurrentIndex(1)
        self.priority_combo.setAccessibleName("Task priority")
        layout.addRow("Priority", self.priority_combo)

        self.recurrence_combo = QComboBox()
        self.recurrence_combo.addItems([r.value.capitalize() for r in Recurrence])
        self.recurrence_combo.setCurrentIndex(0)
        self.recurrence_combo.setAccessibleName("Recurrence pattern")
        layout.addRow("Repeat", self.recurrence_combo)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._accept); btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _accept(self):
        if not self.action_edit.text().strip():
            QMessageBox.warning(self, "Required", "Please enter an action."); return
        self.accept()

    def result_data(self):
        rec_val = list(Recurrence)[self.recurrence_combo.currentIndex()]
        return (
            self.action_edit.text().strip(),
            self.due_dt.dateTime().toString("yyyy-MM-dd HH:mm:ss"),
            self.priority_combo.currentText(),
            rec_val,
        )


# ── Task Detail Dialog ─────────────────────────────────────────────────────────
class TaskDetailDialog(QDialog):
    status_updated = pyqtSignal()

    def __init__(self, task_row, sdb: SchedulerDB, parent=None):
        super().__init__(parent)
        self.task = task_row; self.sdb = sdb; tid = task_row[0]
        self.setWindowTitle(f"📋 Task — {task_row[1][:60]}"); self.resize(600, 520)

        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(16,16,16,16)

        hdr = QFrame()
        hdr.setStyleSheet(f"QFrame{{background:{T('CARD')};border:1px solid {T('BORDER')};border-radius:10px;}}")
        hl = QVBoxLayout(hdr); hl.setContentsMargins(14,12,14,12); hl.setSpacing(6)
        al = QLabel(task_row[1]); al.setWordWrap(True)
        al.setStyleSheet(f"font-size:15px; font-weight:700; color:{T('ACCENT2')}; background:transparent;")
        hl.addWidget(al)
        mr = QHBoxLayout()
        cl = QLabel(f"🕐 Created: {task_row[2]}"); dl = QLabel(f"📅 Due: {task_row[3]}")
        pc = PRIORITY_COLORS.get(task_row[4], T('MUTED'))
        pl = QLabel(f"● {task_row[4]}"); pl.setStyleSheet(f"color:{pc}; font-weight:700; background:transparent;")
        # Show recurrence badge
        rec = task_row[8] if len(task_row) > 8 else "none"
        if rec and rec != "none":
            rl = QLabel(f"🔄 {rec.capitalize()}")
            rl.setStyleSheet(f"color:{T('ACCENT')}; font-size:11px; font-weight:700; background:transparent;")
            mr.addWidget(rl)
        for l in [cl, dl]: l.setStyleSheet(f"color:{T('MUTED')}; font-size:11px; background:transparent;")
        mr.addWidget(cl); mr.addWidget(dl); mr.addStretch(); mr.addWidget(pl)
        hl.addLayout(mr); layout.addWidget(hdr)

        sf = QFrame()
        sf.setStyleSheet(f"QFrame{{background:{T('CARD')};border:1px solid {T('BORDER')};border-radius:10px;}}")
        sl = QVBoxLayout(sf); sl.setContentsMargins(14,10,14,10); sl.setSpacing(8)
        sl.addWidget(section_label("UPDATE STATUS"))
        cr = QHBoxLayout(); cr.setSpacing(8)
        self.status_combo = QComboBox(); self.status_combo.setAccessibleName("Task status")
        self.status_combo.addItems([s.value for s in TaskStatus])
        ci = list(TaskStatus).index(TaskStatus(task_row[5])) if task_row[5] in [s.value for s in TaskStatus] else 0
        self.status_combo.setCurrentIndex(ci)
        self.note_edit = QLineEdit(); self.note_edit.setPlaceholderText("Optional note…")
        self.note_edit.setAccessibleName("Status update note")
        up = accent_btn("💾 Update"); co = success_btn("✅ Mark Complete")
        up.clicked.connect(lambda: self._update_status(tid))
        co.clicked.connect(lambda: self._mark_complete(tid))
        if task_row[7]: co.setEnabled(False); co.setToolTip(f"Completed: {task_row[7]}")
        cr.addWidget(self.status_combo, stretch=1); cr.addWidget(self.note_edit, stretch=2)
        cr.addWidget(up); cr.addWidget(co); sl.addLayout(cr); layout.addWidget(sf)

        layout.addWidget(section_label("STATUS HISTORY"))
        self.log_list = QListWidget(); self.log_list.setAccessibleName("Status history")
        layout.addWidget(self.log_list, stretch=1); self._refresh_logs(tid)

        cb = fmt_btn("Close"); cb.setAccessibleName("Close task detail")
        cb.clicked.connect(self.accept); layout.addWidget(cb, alignment=Qt.AlignmentFlag.AlignRight)

    def _update_status(self, tid):
        self.sdb.update_status(tid, self.status_combo.currentText())
        note = self.note_edit.text().strip()
        if note: self.sdb.add_log(tid, self.status_combo.currentText(), note)
        self.note_edit.clear(); self._refresh_logs(tid); self.status_updated.emit()

    def _mark_complete(self, tid):
        self.sdb.mark_complete(tid); self._refresh_logs(tid); self.status_updated.emit()
        QMessageBox.information(self, "Done!", "Task marked as complete 🎉"); self.accept()

    def _refresh_logs(self, tid):
        self.log_list.clear()
        for logged_at, status, note in self.sdb.logs_for(tid):
            icon  = STATUS_ICONS.get(status, "•")
            label = f"{icon}  {logged_at}  —  {status}"
            if note: label += f"   ·   {note}"
            item = QListWidgetItem(label)
            color = {TaskStatus.DONE: T('GREEN'), TaskStatus.IN_PROGRESS: T('ACCENT2'),
                     TaskStatus.BLOCKED: T('RED')}.get(status, T('MUTED'))
            item.setForeground(QColor(color)); self.log_list.addItem(item)


# ── Scheduler Panel ────────────────────────────────────────────────────────────
class SchedulerPanel(QFrame):
    dates_changed = pyqtSignal()

    def __init__(self, sdb: SchedulerDB, parent=None):
        super().__init__(parent); self.sdb = sdb
        self.setObjectName("schedPanel"); self.setFixedWidth(310)
        layout = QVBoxLayout(self); layout.setContentsMargins(10,12,10,12); layout.setSpacing(6)

        tr = QHBoxLayout()
        tl = QLabel("📅 Scheduler")
        tl.setStyleSheet(f"font-size:16px; font-weight:800; color:{T('ACCENT2')}; background:transparent;")
        self.done_btn = fmt_btn("Show Done", checkable=True, tooltip="Include completed tasks")
        self.done_btn.setAccessibleName("Toggle showing completed tasks")
        self.done_btn.setFixedHeight(26); self.done_btn.toggled.connect(self.refresh)
        tr.addWidget(tl); tr.addStretch(); tr.addWidget(self.done_btn)
        layout.addLayout(tr)

        ab = accent_btn("＋ New Task"); ab.setAccessibleName("Add new task")
        ab.clicked.connect(self.add_task); ab.setFixedHeight(32); layout.addWidget(ab)

        fr = QHBoxLayout()
        self.filter_edit = QLineEdit(); self.filter_edit.setPlaceholderText("Filter tasks…")
        self.filter_edit.setAccessibleName("Filter tasks by keyword")
        self.filter_edit.setClearButtonEnabled(True); self.filter_edit.textChanged.connect(self.refresh)
        self.sort_combo = QComboBox(); self.sort_combo.setAccessibleName("Sort tasks by")
        self.sort_combo.addItems(["Due Date ↑","Priority ↓","Status"])
        self.sort_combo.setFixedWidth(110); self.sort_combo.currentIndexChanged.connect(self.refresh)
        fr.addWidget(self.filter_edit, stretch=1); fr.addWidget(self.sort_combo)
        layout.addLayout(fr)

        self.summary_lbl = QLabel("")
        self.summary_lbl.setStyleSheet(f"color:{T('MUTED')}; font-size:11px; background:transparent; padding:2px 0;")
        layout.addWidget(self.summary_lbl); layout.addWidget(h_sep())

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border:none; background:transparent;")
        self.task_container = QWidget(); self.task_container.setStyleSheet("background:transparent;")
        self.task_vbox = QVBoxLayout(self.task_container)
        self.task_vbox.setContentsMargins(0,0,4,0); self.task_vbox.setSpacing(6)
        self.task_vbox.addStretch(); scroll.setWidget(self.task_container)
        layout.addWidget(scroll, stretch=1)

        self._alert_timer = QTimer(); self._alert_timer.setInterval(60_000)
        self._alert_timer.timeout.connect(self._check_alerts); self._alert_timer.start()
        self._alerted_today: set = set()
        self.refresh()

    def refresh(self):
        show_done = self.done_btn.isChecked()
        rows = self.sdb.all_tasks(show_completed=show_done)
        ft   = self.filter_edit.text().lower()
        if ft: rows = [r for r in rows if ft in r[1].lower() or ft in r[5].lower()]
        si = self.sort_combo.currentIndex()
        if si == 1:
            order = [p.value for p in Priority]; rows = sorted(rows, key=lambda r: order.index(r[4]) if r[4] in order else 99)
        elif si == 2:
            order = [s.value for s in TaskStatus]; rows = sorted(rows, key=lambda r: order.index(r[5]) if r[5] in order else 99)

        all_rows = self.sdb.all_tasks(show_completed=True)
        self.summary_lbl.setText(f"{len([r for r in all_rows if not r[7]])} active  ·  {len(all_rows)} total")

        while self.task_vbox.count() > 1:
            child = self.task_vbox.takeAt(0)
            if child.widget(): child.widget().deleteLater()

        if not rows:
            lbl = QLabel("No tasks found." if ft else "No active tasks.\nClick ＋ to add one.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter); lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color:{T('MUTED')}; padding:20px; background:transparent;")
            self.task_vbox.insertWidget(0, lbl)
        else:
            for i, row in enumerate(rows): self.task_vbox.insertWidget(i, self._make_card(row))
        self.dates_changed.emit()

    def _make_card(self, row):
        tid, action, created_at, due_date, priority, status, completed, completed_at = row[:8]
        recurrence = row[8] if len(row) > 8 else "none"

        card = QFrame()
        is_overdue = (not completed) and (due_date < datetime.datetime.now().strftime(DATE_FMT))
        card.setStyleSheet(
            f"QFrame{{background:{T('CARD')};border:1px solid "
            f"{T('RED') if is_overdue else T('BORDER')};border-radius:10px;}}"
        )
        vl = QVBoxLayout(card); vl.setContentsMargins(12,10,12,10); vl.setSpacing(5)
        tr = QHBoxLayout()
        pc = PRIORITY_COLORS.get(priority, T('MUTED'))
        pl = QLabel(f"● {priority}"); pl.setStyleSheet(f"color:{pc}; font-size:10px; font-weight:700; background:transparent;")
        si = STATUS_ICONS.get(status, "•")
        sl = QLabel(f"{si} {status}"); sl.setStyleSheet(f"color:{T('MUTED')}; font-size:10px; background:transparent;")
        tr.addWidget(pl)
        if recurrence and recurrence != "none":
            rl = QLabel(f"🔄{recurrence[:2].upper()}")
            rl.setStyleSheet(f"color:{T('ACCENT')}; font-size:9px; font-weight:700; background:transparent;")
            tr.addWidget(rl)
        tr.addStretch()
        if is_overdue:
            ov = QLabel("⚠ OVERDUE"); ov.setStyleSheet(f"color:{T('RED')}; font-size:10px; font-weight:700; background:transparent;")
            tr.addWidget(ov); tr.addWidget(QLabel(" "))
        tr.addWidget(sl); vl.addLayout(tr)
        al = QLabel(action[:90] + ("…" if len(action) > 90 else ""))
        al.setWordWrap(True); al.setStyleSheet(f"font-size:12px; font-weight:600; color:{T('TEXT')}; background:transparent;")
        vl.addWidget(al)
        dl = QLabel(f"📅 Due: {due_date[:16]}"); dl.setStyleSheet(f"color:{T('MUTED')}; font-size:10px; background:transparent;")
        vl.addWidget(dl)
        if completed_at:
            cl = QLabel(f"✅ Completed: {completed_at[:16]}")
            cl.setStyleSheet(f"color:{T('GREEN')}; font-size:10px; background:transparent;"); vl.addWidget(cl)
        br = QHBoxLayout(); br.setSpacing(4)
        ob = fmt_btn("📋 Details"); ob.setAccessibleName(f"View details for task: {action[:40]}")
        db = fmt_btn("🗑"); db.setAccessibleName(f"Delete task: {action[:40]}")
        db.setFixedWidth(32); db.setToolTip("Delete task")
        if not completed:
            done_b = success_btn("✅ Done"); done_b.setFixedHeight(26)
            done_b.setAccessibleName(f"Mark task complete: {action[:40]}")
            done_b.clicked.connect(lambda _, t=tid: self._quick_complete(t)); br.addWidget(done_b)
        ob.setFixedHeight(26); db.setFixedHeight(26)
        ob.clicked.connect(lambda _, t=tid: self._open_detail(t))
        db.clicked.connect(lambda _, t=tid: self._delete_task(t))
        br.addStretch(); br.addWidget(ob); br.addWidget(db); vl.addLayout(br)
        return card

    def add_task(self):
        dlg = NewTaskDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            action, due_date, priority, recurrence = dlg.result_data()
            self.sdb.add_task(action, due_date, priority, recurrence); self.refresh()

    def _open_detail(self, tid):
        row = self.sdb.get_task(tid)
        if not row: return
        dlg = TaskDetailDialog(row, self.sdb, self)
        dlg.status_updated.connect(self.refresh); dlg.exec(); self.refresh()

    def _quick_complete(self, tid): self.sdb.mark_complete(tid); self.refresh()

    def _delete_task(self, tid):
        if QMessageBox.question(self, "Delete Task", "Permanently delete this task and its history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.sdb.delete_task(tid); self.refresh()

    def _check_alerts(self):
        now = datetime.datetime.now()
        for row in self.sdb.all_tasks(show_completed=False):
            tid = row[0]; action = row[1]; due_date = row[3]
            due_dt = _safe_parse_dt(due_date)
            if not due_dt: continue
            delta = (due_dt - now).total_seconds()
            key = f"{tid}_{now.date()}"
            if key not in self._alerted_today and -3600 < delta <= 3600:
                self._alerted_today.add(key); self._show_alert(tid, action, due_date, delta)

    def _show_alert(self, tid, action, due_date, delta_seconds):
        msg = (f"⚠ OVERDUE Task\n\n{action}\n\nWas due: {due_date[:16]}" if delta_seconds < 0
               else f"⏰ Task Due Soon ({int(delta_seconds // 60)} min)\n\n{action}\n\nDue: {due_date[:16]}")
        box = QMessageBox(self.parent() or self)
        box.setWindowTitle("Scheduler Alert"); box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.addButton("✅ Mark Complete", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Dismiss",          QMessageBox.ButtonRole.RejectRole)
        if box.exec() == 0: self.sdb.mark_complete(tid); self.refresh()

    def active_due_dates(self): return self.sdb.active_due_dates()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class DiaryApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("✦ Diary")
        self.setMinimumSize(1000, 640)

        # SQLite with WAL for concurrent-safe access
        self.db = sqlite3.connect(DB_NAME, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.create_tables()
        self.ml_db = MasterLockDB(self.db)
        self.sdb   = SchedulerDB(self.db)

        self.current_date     = QDate.currentDate().toString("yyyy-MM-dd")
        self.current_entry_id = None
        self.unsaved          = False
        self._username        = self._load_username()
        self._master_password = SecurePassword()   # zeroed-on-close
        self._tmp_media_paths = []
        self._pending_crypto  = None               # dict during background crypto ops
        self.crypto_worker    = None

        if self.ml_db.has_master_password():
            if not self._show_login():
                QTimer.singleShot(0, QApplication.quit); return

        self.init_ui()
        self.load_entries()
        self.highlight_dates()

        self.timer = QTimer()
        self.timer.timeout.connect(self.auto_save)
        self.timer.start(3000)

        if not self._username:
            QTimer.singleShot(400, self._prompt_master_lock_dialog)

        self.status_bar.set_lock_status(self.ml_db.has_master_password())
        self.showMaximized()   # ← full-screen on startup

    # ── Login ──────────────────────────────────────────────────────────────────
    def _show_login(self) -> bool:
        dlg = MasterLoginDialog(self.ml_db)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._master_password.set(dlg.get_password()); return True
        return False

    # ── DB helpers ─────────────────────────────────────────────────────────────
    def create_tables(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY, date TEXT, title TEXT, content TEXT
            );
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY, value TEXT
            );
        """)
        self.db.commit()

    def _load_username(self):
        r = self.db.execute("SELECT value FROM app_settings WHERE key='username'").fetchone()
        return r[0] if r else ""

    def _save_username(self, name: str):
        self.db.execute(
            "INSERT INTO app_settings (key,value) VALUES('username',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (name,))
        self.db.commit(); self._username = name; self._refresh_username_display()

    def _refresh_username_display(self):
        if self._username:
            self.user_lbl.setText(f"👤  {self._username}"); self.user_lbl.setVisible(True)
        else: self.user_lbl.setVisible(False)

    # ── UI init ────────────────────────────────────────────────────────────────
    def init_ui(self):
        root = QHBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── LEFT PANEL ──────────────────────────────────────────────────────────
        left_frame = QFrame(); left_frame.setObjectName("leftPanel"); left_frame.setFixedWidth(290)
        left = QVBoxLayout(left_frame); left.setContentsMargins(12,12,12,12); left.setSpacing(6)

        trow = QHBoxLayout()
        at = QLabel("✦ Diary")
        at.setStyleSheet(f"font-size:20px; font-weight:800; color:{T('ACCENT2')}; padding:4px 0 2px 0; background:transparent;")
        trow.addWidget(at); trow.addStretch(); left.addLayout(trow)

        urow = QHBoxLayout(); urow.setSpacing(6)
        self.user_lbl = QLabel(f"👤  {self._username}" if self._username else "")
        self.user_lbl.setStyleSheet(
            f"color:{T('ACCENT')}; font-size:12px; font-weight:600; background:transparent; padding:0 2px 6px 2px;"
        )
        self.user_lbl.setCursor(Qt.CursorShape.PointingHandCursor)
        self.user_lbl.setToolTip("Click to manage profile / master lock")
        self.user_lbl.setVisible(bool(self._username))
        self.user_lbl.mousePressEvent = lambda _: self._prompt_master_lock_dialog()

        self.lock_icon_btn = QPushButton()
        self.lock_icon_btn.setFixedSize(30, 30)
        self.lock_icon_btn.setStyleSheet(
            f"QPushButton{{background:transparent;border:none;font-size:16px;border-radius:6px;padding:0;}}"
            f"QPushButton:hover{{background:{T('BORDER')};}}"
        )
        self.lock_icon_btn.clicked.connect(self._prompt_master_lock_dialog)
        self.lock_icon_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.lock_icon_btn.customContextMenuRequested.connect(self._show_lock_menu)
        self._update_lock_icon()
        urow.addWidget(self.user_lbl); urow.addStretch(); urow.addWidget(self.lock_icon_btn)
        left.addLayout(urow)

        self.calendar = QCalendarWidget()
        self.calendar.setAccessibleName("Diary calendar"); self.calendar.setGridVisible(False)
        self.calendar.setVerticalHeaderFormat(QCalendarWidget.VerticalHeaderFormat.NoVerticalHeader)
        self.calendar.setMaximumHeight(230); self.calendar.clicked.connect(self.change_date)
        left.addWidget(self.calendar)

        left.addWidget(section_label("SEARCH"))
        self.search = QLineEdit(); self.search.setPlaceholderText("Search entries…")
        self.search.setAccessibleName("Search diary entries"); self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._debounce_search)
        left.addWidget(self.search)
        self._search_timer = QTimer(); self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._do_search)

        left.addWidget(section_label("ENTRIES"))
        self.entry_list = QListWidget(); self.entry_list.setAccessibleName("Diary entries for selected date")
        self.entry_list.setAlternatingRowColors(False); self.entry_list.itemClicked.connect(self.load_entry)
        self.entry_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.entry_list.customContextMenuRequested.connect(self.list_context_menu)
        left.addWidget(self.entry_list)

        all_btn = QPushButton("📚  View All Entries")
        all_btn.setAccessibleName("View all diary entries"); all_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        all_btn.clicked.connect(self.view_all); left.addWidget(all_btn)
        root.addWidget(left_frame)

        # ── CENTRE PANEL ────────────────────────────────────────────────────────
        centre_widget = QWidget()
        centre = QVBoxLayout(centre_widget); centre.setContentsMargins(0,0,0,0); centre.setSpacing(0)

        top_bar = QWidget(); top_bar.setObjectName("topBar"); top_bar.setFixedHeight(52)
        tbl = QHBoxLayout(top_bar); tbl.setContentsMargins(16,8,16,8); tbl.setSpacing(5)

        self.date_label = QLabel(self.current_date)
        self.date_label.setStyleSheet(f"font-size:16px; font-weight:700; color:{T('ACCENT2')}; background:transparent;")
        tbl.addWidget(self.date_label)
        sv = QFrame(); sv.setFrameShape(QFrame.Shape.VLine); sv.setStyleSheet(f"color:{T('BORDER')};")
        tbl.addWidget(sv)

        # Format buttons
        self.bold_btn   = fmt_btn("B",  checkable=True, tooltip="Bold (Ctrl+B)");   self.bold_btn.setAccessibleName("Bold")
        self.ital_btn   = fmt_btn("I",  checkable=True, tooltip="Italic (Ctrl+I)"); self.ital_btn.setAccessibleName("Italic")
        self.uline_btn  = fmt_btn("U",  checkable=True, tooltip="Underline (Ctrl+U)"); self.uline_btn.setAccessibleName("Underline")
        self.strike_btn = fmt_btn("S̶",  checkable=True, tooltip="Strikethrough"); self.strike_btn.setAccessibleName("Strikethrough")

        sv2 = QFrame(); sv2.setFrameShape(QFrame.Shape.VLine); sv2.setStyleSheet(f"color:{T('BORDER')};")

        # Undo / Redo buttons
        self.undo_btn = fmt_btn("↩", tooltip="Undo (Ctrl+Z)"); self.undo_btn.setAccessibleName("Undo")
        self.redo_btn = fmt_btn("↪", tooltip="Redo (Ctrl+Y)"); self.redo_btn.setAccessibleName("Redo")

        sv3 = QFrame(); sv3.setFrameShape(QFrame.Shape.VLine); sv3.setStyleSheet(f"color:{T('BORDER')};")

        # List buttons
        self.bullet_btn = fmt_btn("• List", tooltip="Bullet list"); self.bullet_btn.setAccessibleName("Bullet list")
        self.num_btn    = fmt_btn("1. List", tooltip="Numbered list"); self.num_btn.setAccessibleName("Numbered list")

        for btn in [self.bold_btn, self.ital_btn, self.uline_btn, self.strike_btn]:
            btn.setFixedHeight(32); tbl.addWidget(btn)
        tbl.addWidget(sv2)
        for btn in [self.undo_btn, self.redo_btn]:
            btn.setFixedHeight(32); tbl.addWidget(btn)
        tbl.addWidget(sv3)
        for btn in [self.bullet_btn, self.num_btn]:
            btn.setFixedHeight(32); tbl.addWidget(btn)

        tbl.addWidget(section_label("SIZE"))
        self.font_size = QSpinBox(); self.font_size.setAccessibleName("Font size")
        self.font_size.setRange(8, 72); self.font_size.setValue(13)
        self.font_size.setFixedWidth(58); self.font_size.setFixedHeight(32)
        tbl.addWidget(self.font_size)

        color_btn = fmt_btn("🎨", tooltip="Text color"); color_btn.setAccessibleName("Text color"); color_btn.setFixedHeight(32)
        tbl.addWidget(color_btn)

        self.emoji_toggle = fmt_btn("😊", checkable=True, tooltip="Toggle emoji picker")
        self.emoji_toggle.setAccessibleName("Toggle emoji picker"); self.emoji_toggle.setFixedHeight(32)
        tbl.addWidget(self.emoji_toggle)

        self.encrypt_toggle = fmt_btn("🔐", checkable=True, tooltip="Toggle Encrypt / Decrypt panel (Ctrl+E)")
        self.encrypt_toggle.setAccessibleName("Toggle encrypt and decrypt panel"); self.encrypt_toggle.setFixedHeight(32)
        tbl.addWidget(self.encrypt_toggle)

        tbl.addStretch()
        new_btn = accent_btn("＋ New Entry"); new_btn.setAccessibleName("Create new diary entry")
        new_btn.setFixedHeight(32); new_btn.clicked.connect(self.new_entry); tbl.addWidget(new_btn)
        centre.addWidget(top_bar)

        inner = QWidget(); inner.setStyleSheet(f"background:{T('DARK')};")
        il = QVBoxLayout(inner); il.setContentsMargins(20,10,20,0); il.setSpacing(8)

        self.emoji_bar = EmojiBar(); self.emoji_bar.emoji_clicked.connect(self.insert_emoji)
        self.emoji_bar.setVisible(False); il.addWidget(self.emoji_bar)

        self.encrypt_panel = EncryptPanel()
        self.encrypt_panel.insert_requested.connect(self.insert_encrypted_snippet); il.addWidget(self.encrypt_panel)

        self.title = QLineEdit(); self.title.setPlaceholderText("Entry title…")
        self.title.setAccessibleName("Entry title"); self.title.setFixedHeight(40)
        self.title.setStyleSheet(
            f"font-size:17px; font-weight:600; padding:6px 12px; "
            f"background:{T('CARD')}; border:1px solid {T('BORDER')}; border-radius:9px; color:{T('TEXT')};"
        )
        il.addWidget(self.title)
        self.editor = DiaryEditor(self); self.editor.textChanged.connect(self.on_text_changed)
        il.addWidget(self.editor, stretch=1)
        centre.addWidget(inner, stretch=1)

        # Action bar
        action_bar = QWidget(); action_bar.setObjectName("actionBar"); action_bar.setFixedHeight(52)
        abl = QHBoxLayout(action_bar); abl.setContentsMargins(16,8,16,8); abl.setSpacing(6)

        save_btn      = accent_btn("💾  Save");      save_btn.setAccessibleName("Save entry")
        delete_btn    = danger_btn("🗑  Delete");    delete_btn.setAccessibleName("Delete entry")
        rename_btn    = fmt_btn("✏️  Rename");       rename_btn.setAccessibleName("Rename entry")
        image_btn     = fmt_btn("🖼  Image");        image_btn.setAccessibleName("Insert image")
        media_btn     = fmt_btn("🎬  Media");        media_btn.setAccessibleName("Insert media file")
        voice_btn     = fmt_btn("🎙  Voice");        voice_btn.setAccessibleName("Record voice memo")
        video_rec_btn = fmt_btn("📹  Video Rec");    video_rec_btn.setAccessibleName("Record video")
        export_btn    = fmt_btn("📄  Export PDF");   export_btn.setAccessibleName("Export entry as PDF")
        export_md_btn = fmt_btn("📝  Export MD");    export_md_btn.setAccessibleName("Export entry as Markdown")

        for btn in [save_btn, delete_btn, rename_btn, image_btn, media_btn,
                    voice_btn, video_rec_btn, export_btn, export_md_btn]:
            btn.setFixedHeight(34); abl.addWidget(btn)
        abl.addStretch(); centre.addWidget(action_bar)

        self.status_bar = StatusBar(); centre.addWidget(self.status_bar)
        root.addWidget(centre_widget, stretch=1)

        # ── RIGHT: SCHEDULER ────────────────────────────────────────────────────
        self.sched_panel = SchedulerPanel(self.sdb, self)
        self.sched_panel.dates_changed.connect(self.highlight_dates)
        root.addWidget(self.sched_panel)

        # Loading overlay
        self.loading_overlay = LoadingOverlay(self); self.loading_overlay.hide()

        # ── Wire all signals ────────────────────────────────────────────────────
        self.bold_btn.clicked.connect(self.fmt_bold)
        self.ital_btn.clicked.connect(self.fmt_italic)
        self.uline_btn.clicked.connect(self.fmt_underline)
        self.strike_btn.clicked.connect(self.fmt_strike)
        self.font_size.valueChanged.connect(self.fmt_size)
        color_btn.clicked.connect(self.fmt_color)
        self.emoji_toggle.toggled.connect(self.emoji_bar.setVisible)
        self.encrypt_toggle.toggled.connect(self._toggle_encrypt_panel)

        # Undo / Redo
        self.undo_btn.clicked.connect(self.editor.undo)
        self.redo_btn.clicked.connect(self.editor.redo)
        self.editor.undoAvailable.connect(self.undo_btn.setEnabled)
        self.editor.redoAvailable.connect(self.redo_btn.setEnabled)
        self.undo_btn.setEnabled(False); self.redo_btn.setEnabled(False)

        # List buttons
        self.bullet_btn.clicked.connect(self.fmt_bullet_list)
        self.num_btn.clicked.connect(self.fmt_numbered_list)

        save_btn.clicked.connect(self.manual_save)
        delete_btn.clicked.connect(self.delete_entry)
        rename_btn.clicked.connect(self.rename)
        image_btn.clicked.connect(self.insert_image)
        media_btn.clicked.connect(self.insert_media)
        voice_btn.clicked.connect(self.record_voice)
        video_rec_btn.clicked.connect(self.record_video)
        export_btn.clicked.connect(self.export_pdf)
        export_md_btn.clicked.connect(self.export_markdown)

        # Keyboard shortcuts
        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self.manual_save)
        QShortcut(QKeySequence("Ctrl+N"), self).activated.connect(self.new_entry)
        QShortcut(QKeySequence("Ctrl+B"), self).activated.connect(self.fmt_bold)
        QShortcut(QKeySequence("Ctrl+I"), self).activated.connect(self.fmt_italic)
        QShortcut(QKeySequence("Ctrl+U"), self).activated.connect(self.fmt_underline)
        QShortcut(QKeySequence("Ctrl+E"), self).activated.connect(
            lambda: self.encrypt_toggle.setChecked(not self.encrypt_toggle.isChecked())
        )
        QShortcut(QKeySequence("Alt+Up"),   self).activated.connect(self.prev_entry)
        QShortcut(QKeySequence("Alt+Down"), self).activated.connect(self.next_entry)

        # Tab order: search → list → title → editor
        QWidget.setTabOrder(self.search, self.entry_list)
        QWidget.setTabOrder(self.entry_list, self.title)
        QWidget.setTabOrder(self.title, self.editor)

    # ── Resize / overlay ───────────────────────────────────────────────────────
    def resizeEvent(self, e):
        super().resizeEvent(e)
        if hasattr(self, "loading_overlay"): self.loading_overlay.resize(self.size())

    def _update_lock_icon(self):
        if self.ml_db.has_master_password():
            self.lock_icon_btn.setText("🔒"); self.lock_icon_btn.setAccessibleName("Master lock on")
            self.lock_icon_btn.setToolTip("Master Lock: ON — click to manage")
        else:
            self.lock_icon_btn.setText("🔓"); self.lock_icon_btn.setAccessibleName("Master lock off")
            self.lock_icon_btn.setToolTip("Master Lock: OFF — click to set password")

    def _show_lock_menu(self, pos):
        menu = QMenu(self)
        menu.addAction("🔒 Master Lock Settings", self._prompt_master_lock_dialog)
        menu.addSeparator()
        menu.addAction("🧹 Clean Orphaned Media", self._clean_orphaned_media)
        menu.exec(self.lock_icon_btn.mapToGlobal(pos))

    def _show_loading(self, message="Processing…"):
        self.loading_overlay.set_message(message)
        self.loading_overlay.resize(self.size()); self.loading_overlay.raise_()
        self.loading_overlay.show()

    def _hide_loading(self):
        self.loading_overlay.hide()

    def _report_media_errors(self, errors):
        if errors:
            details = "\n".join(f"• {n}: {e}" for n, e in errors[:10])
            extra   = f"\n…and {len(errors)-10} more" if len(errors) > 10 else ""
            QMessageBox.warning(self, "Some Media Files Were Skipped",
                f"Diary entries updated, but these media files could not be processed:\n\n"
                f"{details}{extra}\n\nThey were left untouched.")

    # ── Background crypto ops ──────────────────────────────────────────────────
    def _run_crypto_operation(self, operation: str, password: str, old_password: str = ""):
        """Kick off a CryptoWorker thread; disable UI until done."""
        self._pending_crypto = {
            "operation": operation, "password": password, "old_password": old_password
        }
        self.timer.stop()   # pause auto-save
        msg = {"encrypt": "Encrypting all diary data…",
               "decrypt": "Decrypting all diary data…",
               "reencrypt": "Re-encrypting with new password…"}.get(operation, "Processing…")
        self._show_loading(msg)
        self.setEnabled(False)

        self.crypto_worker = CryptoWorker(DB_NAME, password, operation, old_password)
        self.crypto_worker.progress.connect(self._on_crypto_progress)
        self.crypto_worker.finished.connect(self._on_crypto_finished)
        self.crypto_worker.error.connect(self._on_crypto_error)
        self.crypto_worker.start()

    def _on_crypto_progress(self, msg, detail, cur, tot):
        self.loading_overlay.set_message(msg, detail)
        self.loading_overlay.set_progress(cur, tot)

    def _on_crypto_finished(self, errors: list):
        self._hide_loading(); self.setEnabled(True); self.timer.start(3000)
        p = self._pending_crypto
        if not p: return
        op = p["operation"]; pw = p["password"]
        if op == "encrypt":
            self.ml_db.set_master_password(pw); self._master_password.set(pw)
            QMessageBox.information(self, "Master Lock Set",
                "🔒 Master password set!\n\nAll diary data is now encrypted with AES-256-GCM.")
        elif op == "decrypt":
            self.ml_db.remove_master_password(); self._master_password.clear()
            QMessageBox.information(self, "Master Lock Removed",
                "🔓 Master password removed.\n\nAll data is now stored in plaintext.")
        elif op == "reencrypt":
            self.ml_db.set_master_password(pw); self._master_password.set(pw)
            QMessageBox.information(self, "Password Changed", "🔒 Master password changed successfully!")

        self._report_media_errors(errors)
        self._update_lock_icon()
        self.status_bar.set_lock_status(self.ml_db.has_master_password())
        self._invalidate_search_cache()
        self.load_entries()
        if self.current_entry_id: self._load_entry_by_id(self.current_entry_id)
        self._pending_crypto = None

    def _on_crypto_error(self, error_msg: str):
        self._hide_loading(); self.setEnabled(True); self.timer.start(3000)
        QMessageBox.critical(self, "Error", f"Crypto operation failed:\n{error_msg}")
        self._pending_crypto = None

    # ── Master Lock dialog ─────────────────────────────────────────────────────
    def _prompt_master_lock_dialog(self):
        if self.crypto_worker and self.crypto_worker.isRunning(): return
        dlg = MasterLockDialog(self.ml_db, self._username, self._master_password.get(), self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            result = dlg.get_result(); action = result["action"]
            if action == "rename":
                self._save_username(result["new_name"])
            elif action == "set":
                self._run_crypto_operation("encrypt", result["new_pw"])
            elif action == "change":
                self._run_crypto_operation("reencrypt", result["new_pw"], result["cur_pw"])
            elif action == "remove":
                self._run_crypto_operation("decrypt", result["cur_pw"])
            new_name = result.get("new_name", "")
            if new_name and new_name != self._username: self._save_username(new_name)
        else:
            result = dlg.get_result(); new_name = result.get("new_name", "")
            if new_name and new_name != self._username: self._save_username(new_name)

    # ── Decrypt helpers ────────────────────────────────────────────────────────
    def _decrypt_for_display(self, title: str, content: str):
        if self._master_password and self.ml_db.data_is_encrypted():
            return self.ml_db.decrypt_entry_runtime(title, content, self._master_password.get())
        return title, content

    def _encrypt_for_storage(self, title: str, content: str):
        if self._master_password and self.ml_db.data_is_encrypted():
            et = master_encrypt(title,   self._master_password.get()) if title   else ""
            ec = master_encrypt(content, self._master_password.get()) if content else ""
            return et, ec
        return title, content

    def _media_root(self) -> str: return os.path.abspath(MEDIA_FOLDER)

    def _is_safe_media_path(self, path: str) -> bool:
        try:
            root = self._media_root(); target = os.path.abspath(path)
            return os.path.commonpath([root, target]) == root
        except: return False

    def _resolve_media_path(self, path: str):
        if not self._is_safe_media_path(path): return path, path
        enc = path + ".menc"
        if self._master_password and os.path.exists(enc):
            try:
                tmp = self.ml_db.decrypt_media_runtime(enc, self._master_password.get())
                self._tmp_media_paths.append(tmp); return tmp, path
            except Exception as e:
                QMessageBox.warning(self, "Decryption Error", f"Cannot decrypt media:\n{e}")
                return path, path
        return path, path

    def _delete_media_file(self, diary_path: str):
        if not self._is_safe_media_path(diary_path):
            QMessageBox.warning(self, "Delete Media", "File is outside the media folder."); return
        removed = False
        for p in [diary_path, diary_path + ".menc"]:
            if os.path.exists(p):
                try: os.remove(p); removed = True
                except: pass
        if not removed:
            QMessageBox.warning(self, "Delete Media", f"File not found:\n{diary_path}"); return
        base = os.path.basename(diary_path)
        rows = self.db.execute("SELECT id, content FROM entries").fetchall()
        escaped = re.escape(diary_path)
        for eid, content in rows:
            if not content: continue
            new_c = re.sub(rf'<a href="{escaped}"[^>]*>.*?</a>\s*(?:<br>)?', '', content, flags=re.DOTALL)
            if new_c != content: self.db.execute("UPDATE entries SET content=? WHERE id=?", (new_c, eid))
        self.db.commit()
        self._invalidate_search_cache()
        if self.current_entry_id: self._load_entry_by_id(self.current_entry_id)
        QMessageBox.information(self, "Deleted", f"Media removed:\n{base}")

    def _clean_orphaned_media(self):
        """Delete media files in the media folder that are not referenced by any entry."""
        rows = self.db.execute("SELECT content FROM entries").fetchall()
        all_content = " ".join(r[0] or "" for r in rows)
        deleted = []
        for fname in os.listdir(MEDIA_FOLDER):
            fpath = os.path.join(MEDIA_FOLDER, fname)
            base  = fname[:-5] if fname.endswith(".menc") else fname
            # Check if either the base name or the .menc name appears in any entry
            if base not in all_content and fpath not in all_content:
                try: os.remove(fpath); deleted.append(fname)
                except: pass
        if deleted:
            QMessageBox.information(self, "Cleanup Complete",
                f"Removed {len(deleted)} orphaned file(s):\n" + "\n".join(deleted[:20]))
        else:
            QMessageBox.information(self, "Cleanup Complete", "No orphaned media files found.")

    # ── Encrypt panel ──────────────────────────────────────────────────────────
    def _toggle_encrypt_panel(self, checked: bool):
        self.encrypt_panel.setVisible(checked)
        if checked and not CRYPTO_OK:
            QMessageBox.information(self, "Install Required",
                "pip install cryptography\n\nThen restart the app.")

    def insert_encrypted_snippet(self, token: str):
        self.editor.insertHtml(make_encrypted_snippet(token))
        self.editor.setFocus(); self.encrypt_toggle.setChecked(False)

    # ── Formatting ─────────────────────────────────────────────────────────────
    def fmt_bold(self):
        w = self.editor.fontWeight()
        self.editor.setFontWeight(QFont.Weight.Normal if w == QFont.Weight.Bold else QFont.Weight.Bold)
        self.bold_btn.setChecked(self.editor.fontWeight() == QFont.Weight.Bold)

    def fmt_italic(self):
        v = not self.editor.fontItalic(); self.editor.setFontItalic(v); self.ital_btn.setChecked(v)

    def fmt_underline(self):
        v = not self.editor.fontUnderline(); self.editor.setFontUnderline(v); self.uline_btn.setChecked(v)

    def fmt_strike(self):
        fmt = self.editor.currentCharFormat(); v = not fmt.fontStrikeOut()
        fmt.setFontStrikeOut(v); self.editor.mergeCurrentCharFormat(fmt); self.strike_btn.setChecked(v)

    def fmt_size(self, s): self.editor.setFontPointSize(s)

    def fmt_color(self):
        c = QColorDialog.getColor(parent=self)
        if c.isValid(): self.editor.setTextColor(c)

    def fmt_bullet_list(self):
        cursor = self.editor.textCursor()
        lf = QTextListFormat(); lf.setStyle(QTextListFormat.Style.ListDisc)
        cursor.createList(lf)

    def fmt_numbered_list(self):
        cursor = self.editor.textCursor()
        lf = QTextListFormat(); lf.setStyle(QTextListFormat.Style.ListDecimal)
        cursor.createList(lf)

    def insert_emoji(self, emoji):
        self.editor.insertPlainText(emoji); self.editor.setFocus()

    # ── Entry navigation ───────────────────────────────────────────────────────
    def prev_entry(self):
        row = self.entry_list.currentRow()
        if row > 0:
            self.entry_list.setCurrentRow(row - 1)
            self.load_entry(self.entry_list.currentItem())

    def next_entry(self):
        row = self.entry_list.currentRow()
        if row < self.entry_list.count() - 1:
            self.entry_list.setCurrentRow(row + 1)
            self.load_entry(self.entry_list.currentItem())

    # ── Link handler ───────────────────────────────────────────────────────────
    def handle_link(self, url: str):
        if url.startswith(CRYPTO_PREFIX):
            DecryptDialog(url, self).exec()
        else:
            actual, diary = self._resolve_media_path(url)
            if os.path.exists(actual):
                ext = os.path.splitext(actual)[1].lower()
                if ext in IMAGE_EXTS:
                    v = ImageViewer(actual, self, diary_path=diary)
                    v.delete_requested.connect(self._delete_media_file); v.exec()
                else:
                    p = MediaPlayer(actual, self, diary_path=diary)
                    p.delete_requested.connect(self._delete_media_file); p.exec()
            else:
                QMessageBox.warning(self, "Not Found", f"Could not open:\n{url}")

    # ── Search (debounced + cached) ────────────────────────────────────────────
    def _debounce_search(self):
        self._search_timer.stop(); self._search_timer.start(300)

    def _build_search_cache(self):
        if hasattr(self, '_search_cache'): return
        self.status_bar.saved_label.setText("⟳ Indexing…")
        QApplication.processEvents()
        cur = self.db.cursor()
        cur.execute("SELECT id, date, title, content FROM entries ORDER BY date DESC")
        self._search_cache = []
        for eid, date, title, content in cur.fetchall():
            pt, pc = self._decrypt_for_display(title or "", content or "")
            self._search_cache.append((eid, date, pt or "Untitled", self._html_to_text(pc)))
        self.status_bar.set_saved(not self.unsaved)

    def _invalidate_search_cache(self):
        if hasattr(self, '_search_cache'): del self._search_cache

    def _do_search(self):
        text = self.search.text().lower().strip()
        self.entry_list.clear()
        if not text: self._populate_entry_list(); return

        if self._master_password and self.ml_db.data_is_encrypted():
            self._build_search_cache()
            for eid, date, pt, plain_text in self._search_cache:
                if text in (date + pt + plain_text).lower():
                    item = QListWidgetItem(f"📅 {date}  —  {pt}")
                    item.setData(Qt.ItemDataRole.UserRole, eid)
                    self.entry_list.addItem(item)
        else:
            cur = self.db.cursor()
            cur.execute(
                "SELECT id, date, title FROM entries "
                "WHERE lower(title) LIKE ? OR lower(content) LIKE ? ORDER BY date DESC",
                (f"%{text}%", f"%{text}%"))
            for eid, date, title in cur.fetchall():
                item = QListWidgetItem(f"📅 {date}  —  {title or 'Untitled'}")
                item.setData(Qt.ItemDataRole.UserRole, eid)
                self.entry_list.addItem(item)

    def search_entries(self): self._debounce_search()  # legacy alias

    # ── File insert (with styled audio/video blocks) ───────────────────────────
    def insert_file(self, src_path: str):
        name = os.path.basename(src_path)
        dest = os.path.join(MEDIA_FOLDER, name)
        base, ext = os.path.splitext(name); counter = 1
        while os.path.exists(dest) and os.path.abspath(src_path) != os.path.abspath(dest):
            dest = os.path.join(MEDIA_FOLDER, f"{base}_{counter}{ext}"); counter += 1
        if os.path.abspath(src_path) != os.path.abspath(dest):
            try: shutil.copy2(src_path, dest)
            except Exception as e:
                QMessageBox.warning(self, "Insert Error", f"Could not copy file:\n{e}"); return

        if self._master_password and self.ml_db.data_is_encrypted():
            try: master_encrypt_file(dest, self._master_password.get()); os.remove(dest)
            except Exception as e: QMessageBox.warning(self, "Encrypt Error", f"Could not encrypt media:\n{e}")

        ext_l = ext.lower()
        if ext_l in IMAGE_EXTS:
            self.editor.insertHtml(
                f'<a href="{dest}"><img src="{dest}" width="220" '
                f'style="border-radius:8px; margin:4px;"></a><br>'
            )
        elif ext_l in AUDIO_EXTS:
            self.editor.insertHtml(make_audio_snippet(dest, name))
        elif ext_l in VIDEO_EXTS:
            self.editor.insertHtml(make_video_snippet(dest, name))
        else:
            self.editor.insertHtml(
                f'<a href="{dest}" style="color:{T("ACCENT")};">📎 {name}</a><br>'
            )

    def insert_image(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Image", "",
                                           "Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)")
        if f: self.insert_file(f)

    def insert_media(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Media File", "",
            "Media (*.mp3 *.wav *.ogg *.flac *.aac *.m4a *.mp4 *.avi *.mkv *.mov *.webm)")
        if f: self.insert_file(f)

    def record_voice(self):
        dlg = RecorderDialog(with_video=False, parent=self); dlg.file_saved.connect(self.insert_file); dlg.exec()

    def record_video(self):
        dlg = RecorderDialog(with_video=True, parent=self); dlg.file_saved.connect(self.insert_file); dlg.exec()

    # ── Export ─────────────────────────────────────────────────────────────────
    def export_pdf(self):
        if self.current_entry_id is None:
            QMessageBox.information(self, "Export PDF", "No entry selected."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export as PDF",
                                              f"{self.title.text() or 'entry'}.pdf", "PDF (*.pdf)")
        if not path: return
        try:
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout.Unit.Millimeter)
            doc = QTextDocument()
            doc.setHtml(
                f"<html><head><style>"
                f"body{{font-family:'Segoe UI',sans-serif;font-size:13pt;color:#1a1a2e;line-height:1.7;}}"
                f"h1{{color:#4338ca;margin-bottom:4px;}}p.meta{{color:#4a5568;font-size:11pt;margin-top:0;}}"
                f"hr{{border:none;border-top:1px solid #c5cde0;margin:16px 0;}}"
                f"</style></head><body>"
                f"<h1>{self.title.text() or 'Untitled'}</h1>"
                f"<p class='meta'>{self.current_date}</p><hr>"
                f"{self.editor.toHtml()}</body></html>"
            )
            doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.Point).size()))
            doc.print(printer)
            QMessageBox.information(self, "Export PDF", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Error", f"Could not export PDF:\n{e}")

    def export_markdown(self):
        """Export current entry as Markdown / plain text."""
        if self.current_entry_id is None:
            QMessageBox.information(self, "Export", "No entry selected."); return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export as Markdown",
            f"{self.title.text() or 'entry'}.md",
            "Markdown (*.md);;Plain text (*.txt)")
        if not path: return
        title = self.title.text() or "Untitled"
        body  = self.editor.toPlainText()
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# {title}\n\n_{self.current_date}_\n\n{body}\n")
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Error", f"Could not save file:\n{e}")

    def export_all_pdf(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export All as PDF", "diary_all.pdf", "PDF (*.pdf)")
        if not path: return
        try:
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            printer.setPageMargins(QMarginsF(20, 20, 20, 20), QPageLayout.Unit.Millimeter)
            rows = self.db.execute("SELECT date, title, content FROM entries ORDER BY date DESC").fetchall()
            combined = (
                "<html><head><style>"
                "body{font-family:'Segoe UI',sans-serif;font-size:13pt;color:#1a1a2e;line-height:1.7;}"
                "h1{color:#4338ca;margin-bottom:4px;} p.meta{color:#4a5568;font-size:11pt;margin-top:0;}"
                "hr{border:none;border-top:1px solid #c5cde0;margin:24px 0;}"
                "</style></head><body>"
            )
            for dt, t, c in rows:
                pt, pc = self._decrypt_for_display(t, c)
                combined += f"<h1>{pt or 'Untitled'}</h1><p class='meta'>📅 {dt}</p><hr>{pc or ''}<br><br>"
            combined += "</body></html>"
            doc = QTextDocument(); doc.setHtml(combined)
            doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.Point).size())); doc.print(printer)
            QMessageBox.information(self, "Export All PDF", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Error", f"Could not export PDF:\n{e}")

    # ── Entries CRUD ───────────────────────────────────────────────────────────
    def new_entry(self):
        if self.unsaved: self._prompt_save()
        self.editor.clear(); self.title.clear()
        self.current_entry_id = None; self.unsaved = False
        self.status_bar.set_saved(True); self.editor.setFocus()

    def change_date(self):
        if self.unsaved: self._prompt_save()
        self.current_date = self.calendar.selectedDate().toString("yyyy-MM-dd")
        self.date_label.setText(self.current_date)
        self.editor.clear(); self.title.clear()
        self.current_entry_id = None; self.unsaved = False
        self.status_bar.set_saved(True); self.load_entries()

    def load_entries(self): self.entry_list.clear(); self._populate_entry_list()

    def _populate_entry_list(self):
        for eid, title in self.db.execute(
            "SELECT id, title FROM entries WHERE date=? ORDER BY id DESC", (self.current_date,)
        ).fetchall():
            display = title or "Untitled"
            if display.startswith(MASTER_PREFIX): display = "🔒 Encrypted Entry"
            item = QListWidgetItem(f"  {display}")
            item.setData(Qt.ItemDataRole.UserRole, eid); self.entry_list.addItem(item)

    def load_entry(self, item):
        eid = item.data(Qt.ItemDataRole.UserRole); self._load_entry_by_id(eid)

    def _load_entry_by_id(self, eid):
        if eid is None: return
        row = self.db.execute("SELECT date,title,content FROM entries WHERE id=?", (eid,)).fetchone()
        if not row: return
        self.current_date = row[0]; self.date_label.setText(self.current_date)
        qd = QDate.fromString(self.current_date, "yyyy-MM-dd")
        self.calendar.blockSignals(True)
        if qd.isValid(): self.calendar.setSelectedDate(qd)
        self.calendar.blockSignals(False)
        pt, pc = self._decrypt_for_display(row[1], row[2])
        self.title.setText(pt or ""); self.editor.setHtml(pc or "")
        self.current_entry_id = eid; self.unsaved = False; self.status_bar.set_saved(True)
        self.load_entries()
        for i in range(self.entry_list.count()):
            it = self.entry_list.item(i)
            if it.data(Qt.ItemDataRole.UserRole) == eid:
                self.entry_list.setCurrentItem(it); break

    def on_text_changed(self):
        self.unsaved = True; self.status_bar.set_saved(False)
        self.status_bar.update_counts(self.editor.toPlainText())

    def auto_save(self):
        if self.unsaved and self.editor.toPlainText().strip(): self._save()

    def manual_save(self): self._save()

    def _save(self):
        try:
            title   = self.title.text().strip() or "Untitled"
            content = self.editor.toHtml()
            st, sc  = self._encrypt_for_storage(title, content)
            cur     = self.db.cursor()
            if self.current_entry_id is None:
                cur.execute("INSERT INTO entries VALUES (NULL,?,?,?)", (self.current_date, st, sc))
                self.current_entry_id = cur.lastrowid
            else:
                cur.execute("UPDATE entries SET title=?,content=? WHERE id=?",
                            (st, sc, self.current_entry_id))
            self.db.commit(); self.unsaved = False; self.status_bar.set_saved(True)
            self._invalidate_search_cache(); self.load_entries(); self.highlight_dates()
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Could not save entry:\n{e}")

    def delete_entry(self):
        if self.current_entry_id is None: return
        if QMessageBox.question(self, "Delete Entry", "Permanently delete this entry?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            self.db.execute("DELETE FROM entries WHERE id=?", (self.current_entry_id,))
            self.db.commit(); self.editor.clear(); self.title.clear()
            self.current_entry_id = None; self.unsaved = False; self.status_bar.set_saved(True)
            self._invalidate_search_cache(); self.load_entries(); self.highlight_dates()

    def rename(self):
        if self.current_entry_id is None: return
        new, ok = QInputDialog.getText(self, "Rename Entry", "New title:", text=self.title.text())
        if ok and new.strip(): self.title.setText(new.strip()); self._save()

    # ── View All ───────────────────────────────────────────────────────────────
    def view_all(self):
        d = QDialog(self); d.setWindowTitle("All Entries"); d.resize(980, 740)
        layout = QVBoxLayout(d); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)

        header = QWidget(); header.setStyleSheet(f"background:{T('PANEL')};border-bottom:1px solid {T('BORDER')};")
        hl = QHBoxLayout(header); hl.setContentsMargins(14,10,14,10); hl.setSpacing(10)
        sb = QLineEdit(); sb.setPlaceholderText("Filter entries…"); sb.setAccessibleName("Filter all entries"); sb.setClearButtonEnabled(True)
        exp = accent_btn("📤 Export All as PDF"); exp.clicked.connect(self.export_all_pdf)
        hl.addWidget(sb, stretch=1); hl.addWidget(exp); layout.addWidget(header)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"border:none; background:{T('DARK')};")
        container = QWidget(); container.setStyleSheet(f"background:{T('DARK')};")
        self._all_layout = QVBoxLayout(container)
        self._all_layout.setContentsMargins(16,16,16,16); self._all_layout.setSpacing(10)
        scroll.setWidget(container); layout.addWidget(scroll)

        rows = self.db.execute("SELECT id, date, title, content FROM entries ORDER BY date DESC").fetchall()

        def _preview(html, n=160):
            t = self._html_to_text(html).strip(); t = " ".join(t.split())
            return t[:n] + ("…" if len(t) > n else "")

        def render(ft=""):
            while self._all_layout.count():
                ch = self._all_layout.takeAt(0)
                if ch.widget(): ch.widget().deleteLater()
            shown = 0
            for eid, dt, t, c in rows:
                pt, pc = self._decrypt_for_display(t, c)
                if ft and ft.lower() not in ((dt or "")+(pt or "")+self._html_to_text(pc)).lower(): continue
                card = EntryCard(eid, dt, pt, _preview(pc))
                def _open(ei, dg=d): dg.accept(); self._load_entry_by_id(ei)
                card.open_requested.connect(_open); self._all_layout.addWidget(card); shown += 1
            if shown == 0:
                lbl = QLabel("No entries found."); lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                lbl.setStyleSheet(f"color:{T('MUTED')}; padding:40px; background:transparent;")
                self._all_layout.addWidget(lbl)
            self._all_layout.addStretch()

        render(); sb.textChanged.connect(render); d.exec()

    # ── Calendar highlights ────────────────────────────────────────────────────
    def highlight_dates(self):
        self.calendar.setDateTextFormat(QDate(), QTextCharFormat())
        df = QTextCharFormat(); df.setBackground(QColor(T('ACCENT'))); df.setForeground(QColor("#ffffff"))
        for (dt,) in self.db.execute("SELECT DISTINCT date FROM entries").fetchall():
            qd = QDate.fromString(dt, "yyyy-MM-dd")
            if qd.isValid(): self.calendar.setDateTextFormat(qd, df)
        sf = QTextCharFormat(); sf.setBackground(QColor(T('ORANGE'))); sf.setForeground(QColor("#ffffff"))
        for dt in self.sched_panel.active_due_dates():
            qd = QDate.fromString(dt[:10], "yyyy-MM-dd")
            if not qd.isValid(): continue
            ex = self.calendar.dateTextFormat(qd)
            if ex.background().color().isValid() and ex.background().color() == QColor(T('ACCENT')):
                cf = QTextCharFormat(); cf.setBackground(QColor(T('ACCENT')))
                cf.setForeground(QColor(T('ORANGE'))); cf.setFontWeight(QFont.Weight.Bold)
                self.calendar.setDateTextFormat(qd, cf)
            else: self.calendar.setDateTextFormat(qd, sf)

    # ── Context menus ──────────────────────────────────────────────────────────
    def list_context_menu(self, pos):
        item = self.entry_list.itemAt(pos)
        if not item: return
        menu = QMenu(self)
        menu.addAction("📂  Load Entry",   lambda: self.load_entry(item))
        menu.addSeparator()
        menu.addAction("🗑  Delete Entry", lambda: self._delete_item(item))
        menu.exec(self.entry_list.mapToGlobal(pos))

    def _delete_item(self, item):
        eid = item.data(Qt.ItemDataRole.UserRole)
        if eid is None: return
        self.db.execute("DELETE FROM entries WHERE id=?", (eid,)); self.db.commit()
        if self.current_entry_id == eid:
            self.editor.clear(); self.title.clear(); self.current_entry_id = None
        self._invalidate_search_cache(); self.load_entries(); self.highlight_dates()

    def _prompt_save(self):
        reply = QMessageBox.question(self, "Unsaved Changes",
            "Save current entry before continuing?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Save: self._save()

    # ── Cleanup ────────────────────────────────────────────────────────────────
    @staticmethod
    def _html_to_text(html: str) -> str:
        doc = QTextDocument(); doc.setHtml(html or ""); return doc.toPlainText()

    def _cleanup_tmp_media(self):
        for tmp in self._tmp_media_paths:
            try:
                if os.path.exists(tmp): os.remove(tmp)
                d = os.path.dirname(tmp)
                if os.path.isdir(d) and not os.listdir(d): shutil.rmtree(d, ignore_errors=True)
            except: pass
        self._tmp_media_paths.clear()

    def closeEvent(self, e):
        if self.crypto_worker and self.crypto_worker.isRunning():
            QMessageBox.information(self, "Please Wait",
                "A crypto operation is still running.\nPlease wait before closing.")
            e.ignore(); return
        if self.unsaved:
            reply = QMessageBox.question(self, "Unsaved Changes",
                "Save before closing?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel)
            if reply == QMessageBox.StandardButton.Save:  self._save()
            elif reply == QMessageBox.StandardButton.Cancel: e.ignore(); return
        self._cleanup_tmp_media()
        self._master_password.clear()   # zero the password bytes
        self.db.close()
        super().closeEvent(e)


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(build_stylesheet())
    app.setFont(QFont("Segoe UI", 10))
    w = DiaryApp()
    sys.exit(app.exec())
