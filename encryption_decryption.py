import tkinter as tk
from tkinter import scrolledtext
from abc import ABC, abstractmethod
import sqlite3
import os
from datetime import datetime

# Try to import Pillow; gracefully fall back if not installed
try:
    from PIL import Image, ImageTk, ImageDraw
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# ─── Colour / Font Constants ────────────────────────────────────────────────
BG    = "#0b0f14"
PANEL = "#111827"
GREEN = "#00ff9c"
BLUE  = "#38bdf8"
RED   = "#f43f5e"
TEXT  = "#e5e7eb"
GOLD  = "#fbbf24"

FONT  = ("Consolas", 11)
TITLE = ("Consolas", 16, "bold")
SMALL = ("Consolas", 9)


# ════════════════════════════════════════════════════════════════════════════
# CUSTOM DATA STRUCTURE — Linked List
# ════════════════════════════════════════════════════════════════════════════
class Node:
    """A single node in the singly-linked history list."""
    def __init__(self, data):
        self.data = data   # dict: {algorithm, original, result, operation, timestamp}
        self.next = None


class LinkedList:
    """Custom singly-linked list for in-memory encryption history.
    Does NOT use Python's built-in list as underlying storage.
    """
    def __init__(self):
        self.head = None
        self.size = 0

    def insert(self, data):
        """Append a new node to the tail. O(n) time."""
        new_node = Node(data)
        if not self.head:
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node
        self.size += 1

    def traverse(self):
        """Return all node data as a plain list (for GUI display). O(n)."""
        items = []
        current = self.head
        while current:
            items.append(current.data)
            current = current.next
        return items


# ════════════════════════════════════════════════════════════════════════════
# PERSISTENCE MANAGER — SQLite + Flat File (Dual Persistence)
# ════════════════════════════════════════════════════════════════════════════
class PersistenceManager:
    """Handles dual persistence: SQLite database AND plain-text log file.

    Every encryption/decryption event is written to:
      1. cyber_vault.db  — SQLite relational database (survives app restarts)
      2. session_log.txt — Human-readable flat-file audit log

    Args:
        db_path  (str): Path to SQLite database file.
        log_path (str): Path to plain-text log file.
    """

    def __init__(self, db_path="cyber_vault.db", log_path="session_log.txt"):
        self.db_path  = db_path
        self.log_path = log_path
        self._setup_database()

    # ── Private ─────────────────────────────────────────────────────────────
    def _setup_database(self):
        """Create the encryption_history table if it doesn't already exist."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS encryption_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT    NOT NULL,
                operation TEXT    NOT NULL,
                original  TEXT    NOT NULL,
                result    TEXT    NOT NULL,
                timestamp TEXT    NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    # ── Public ──────────────────────────────────────────────────────────────
    def save_record(self, record: dict):
        """Write one record to BOTH the SQLite database and the log file.

        Args:
            record (dict): Keys — algorithm, operation, original, result, timestamp.
        """
        # 1. Write to SQLite
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO encryption_history "
                "(algorithm, operation, original, result, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (record["algorithm"], record["operation"],
                 record["original"],  record["result"],
                 record["timestamp"])
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"[DB ERROR] {e}")

        # 2. Write to flat-file log
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(
                    f"[{record['timestamp']}] "
                    f"{record['algorithm']} | {record['operation']}: "
                    f"{record['original']} -> {record['result']}\n"
                )
        except OSError as e:
            print(f"[LOG ERROR] {e}")

    def load_history(self):
        """Load all previous records from SQLite on startup.

        Returns:
            list[dict]: Ordered list of all historical records.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                "SELECT algorithm, operation, original, result, timestamp "
                "FROM encryption_history ORDER BY id"
            )
            rows = cursor.fetchall()
            conn.close()
            return [
                {"algorithm": r[0], "operation": r[1],
                 "original":  r[2], "result":    r[3], "timestamp": r[4]}
                for r in rows
            ]
        except sqlite3.Error as e:
            print(f"[DB LOAD ERROR] {e}")
            return []

    def get_record_count(self):
        """Return total number of records stored in the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            count = conn.execute(
                "SELECT COUNT(*) FROM encryption_history").fetchone()[0]
            conn.close()
            return count
        except sqlite3.Error:
            return 0


# ════════════════════════════════════════════════════════════════════════════
# CIPHER HIERARCHY — Abstract Base + Two Concrete Implementations
# ════════════════════════════════════════════════════════════════════════════
class Cipher(ABC):
    """Abstract base class enforcing the encrypt/decrypt interface."""

    @abstractmethod
    def encrypt(self, plaintext, key):
        """Encrypt plaintext with the given key. Returns ciphertext string."""
        pass

    @abstractmethod
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext with the given key. Returns plaintext string."""
        pass


class CaesarCipher(Cipher):
    """Caesar Cipher — shifts each alphabetical character by an integer key.

    Time Complexity : O(n) where n = len(plaintext)
    Space Complexity: O(n) for the output string
    Non-alpha chars : preserved unchanged (spaces, digits, punctuation)
    """

    def encrypt(self, plaintext, key):
        """Shift each letter forward by key positions (mod 26).

        Args:
            plaintext (str): Input text to encrypt.
            key       (int|str): Shift value; converted to int internally.
        Returns:
            str: Encrypted ciphertext.
        """
        result = ""
        shift  = int(key)
        for char in plaintext:
            if char.isalpha():
                base    = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char   # preserve non-alpha characters
        return result

    def decrypt(self, ciphertext, key):
        """Reverse encryption by applying a negative shift.

        Args:
            ciphertext (str): Encrypted text to decrypt.
            key        (int|str): Original shift value.
        Returns:
            str: Recovered plaintext.
        """
        return self.encrypt(ciphertext, -int(key))


class XorCipher(Cipher):
    """XOR Cipher — applies bitwise XOR between each char and a repeating key.

    The key is a string; it repeats cyclically across the input (Vigenère-style
    at the byte level). Because XOR is self-inverse, encrypt == decrypt.

    Time Complexity : O(n) where n = len(plaintext)
    Space Complexity: O(n) for the output string
    """

    def encrypt(self, plaintext, key):
        """XOR each character of plaintext with the cycling key string.

        Args:
            plaintext (str): Input text to encrypt.
            key       (str): Key string (repeats if shorter than plaintext).
        Returns:
            str: XOR-encrypted result.
        """
        result = ""
        for i, char in enumerate(plaintext):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result

    def decrypt(self, ciphertext, key):
        """XOR is self-inverse — decryption is identical to encryption.

        Args:
            ciphertext (str): Encrypted text to decrypt.
            key        (str): Same key used during encryption.
        Returns:
            str: Recovered plaintext.
        """
        return self.encrypt(ciphertext, key)


# ════════════════════════════════════════════════════════════════════════════
# ENCRYPTION MANAGER — Facade coordinating ciphers, history, persistence
# ════════════════════════════════════════════════════════════════════════════
class EncryptionManager:
    """Facade that decouples the GUI from cipher implementations.

    Coordinates:
      - Algorithm selection via dictionary lookup (O(1))
      - In-memory history via custom LinkedList
      - Dual persistence via PersistenceManager
    """

    def __init__(self):
        self.history    = LinkedList()
        self.persistence = PersistenceManager()
        self.ciphers = {
            "CAESAR": CaesarCipher(),
            "XOR":    XorCipher()
        }
        # Load previous session records from SQLite into the linked list
        for record in self.persistence.load_history():
            self.history.insert(record)

    def encrypt(self, algorithm, message, key):
        """Encrypt message, record in linked list + both persistence stores.

        Args:
            algorithm (str): 'CAESAR' or 'XOR'.
            message   (str): Plaintext to encrypt.
            key       (str): Key value.
        Returns:
            str: Encrypted ciphertext.
        """
        cipher    = self.ciphers[algorithm]
        encrypted = cipher.encrypt(message, key)
        record    = {
            "algorithm": algorithm,
            "operation": "ENCRYPT",
            "original":  message,
            "result":    encrypted,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.history.insert(record)
        self.persistence.save_record(record)
        return encrypted

    def decrypt(self, algorithm, message, key):
        """Decrypt message, record in linked list + both persistence stores.

        Args:
            algorithm (str): 'CAESAR' or 'XOR'.
            message   (str): Ciphertext to decrypt.
            key       (str): Key value.
        Returns:
            str: Decrypted plaintext.
        """
        cipher    = self.ciphers[algorithm]
        decrypted = cipher.decrypt(message, key)
        record    = {
            "algorithm": algorithm,
            "operation": "DECRYPT",
            "original":  message,
            "result":    decrypted,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.history.insert(record)
        self.persistence.save_record(record)
        return decrypted

    def get_history(self):
        """Return all session history records from the linked list."""
        return self.history.traverse()

    def get_db_record_count(self):
        """Return total records stored in the SQLite database."""
        return self.persistence.get_record_count()


# ════════════════════════════════════════════════════════════════════════════
# GUI — Tkinter with Pillow banner (third-party library)
# ════════════════════════════════════════════════════════════════════════════
def _create_banner_image():
    """Use Pillow to programmatically generate a cyberpunk banner image.

    Returns:
        ImageTk.PhotoImage | None: Tkinter-compatible image, or None if
        Pillow is unavailable.
    """
    if not PILLOW_AVAILABLE:
        return None
    try:
        # Create a 900x60 banner using Pillow's ImageDraw
        img  = Image.new("RGB", (900, 60), color="#111827")
        draw = ImageDraw.Draw(img)

        # Neon green left bar
        draw.rectangle([0, 0, 6, 60], fill="#00ff9c")

        # Title text (Pillow default font — no external font file needed)
        draw.text((20, 10), "CYBER VAULT  ::  ENCRYPTION LAB",
                  fill="#00ff9c")
        draw.text((20, 35), "Powered by Python  |  Caesar & XOR Ciphers  |  SQLite Persistence",
                  fill="#38bdf8")

        # Right-side decorative neon bar
        draw.rectangle([893, 0, 900, 60], fill="#38bdf8")

        return ImageTk.PhotoImage(img)
    except Exception:
        return None


class EncryptionGUI:
    """Main GUI class. Builds and manages all Tkinter widgets."""

    def __init__(self, root):
        self.manager   = EncryptionManager()
        self.algorithm = "CAESAR"

        root.title("CYBER VAULT :: ENCRYPTION LAB")
        root.geometry("920x700")
        root.configure(bg=BG)
        root.resizable(False, False)

        self._build_header(root)
        self._build_body(root)
        self._build_history_panel(root)
        self._refresh_history_display()

    # ── Layout builders ─────────────────────────────────────────────────────
    def _build_header(self, root):
        """Header: Pillow-rendered banner image (or text fallback)."""
        header = tk.Frame(root, bg=PANEL, height=60)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Attempt Pillow banner
        self._banner_img = _create_banner_image()
        if self._banner_img:
            tk.Label(header, image=self._banner_img, bg=PANEL).pack(side="left")
        else:
            # Fallback plain-text header (no Pillow)
            tk.Label(header, text="CYBER VAULT :: ENCRYPTION LAB",
                     fg=GREEN, bg=PANEL, font=TITLE).pack(side="left", padx=20)

        self.status = tk.Label(header, text="🔒 STATUS: SECURE",
                               fg=GREEN, bg=PANEL, font=FONT)
        self.status.pack(side="right", padx=20)

    def _build_body(self, root):
        """Central body: inputs, controls, output console."""
        body = tk.Frame(root, bg=BG)
        body.pack(fill="x", padx=20, pady=(10, 0))

        # Message input
        tk.Label(body, text="▸ MESSAGE INPUT",
                 fg=BLUE, bg=BG, font=FONT).pack(anchor="w")
        self.msg = tk.Text(body, height=4, bg=PANEL, fg=TEXT,
                           font=FONT, insertbackground=GREEN,
                           relief="flat", bd=2)
        self.msg.pack(fill="x", pady=(2, 8))

        # Key input + strength meter
        key_frame = tk.Frame(body, bg=BG)
        key_frame.pack(fill="x")
        tk.Label(key_frame, text="▸ ENCRYPTION KEY",
                 fg=BLUE, bg=BG, font=FONT).pack(anchor="w")
        self.key = tk.Entry(key_frame, bg=PANEL, fg=TEXT,
                            font=FONT, insertbackground=GREEN, relief="flat")
        self.key.pack(fill="x", pady=(2, 4))
        self.key.bind("<KeyRelease>", self.check_key_strength)

        self.key_strength = tk.Label(body, text="Key Strength: UNKNOWN",
                                     fg=RED, bg=BG, font=FONT)
        self.key_strength.pack(anchor="w", pady=(0, 8))

        # Algorithm + action buttons
        btns = tk.Frame(body, bg=BG)
        btns.pack(pady=6)

        self.caesar_btn = tk.Button(
            btns, text="[ CAESAR ]", bg=GREEN, fg="black",
            font=FONT, width=13, relief="flat",
            command=lambda: self.set_algo("CAESAR"))
        self.caesar_btn.pack(side="left", padx=4)

        self.xor_btn = tk.Button(
            btns, text="[ XOR ]", bg=PANEL, fg=BLUE,
            font=FONT, width=13, relief="flat",
            command=lambda: self.set_algo("XOR"))
        self.xor_btn.pack(side="left", padx=4)

        tk.Button(btns, text="ENCRYPT", bg="#16a34a", fg="white",
                  font=FONT, width=13, relief="flat",
                  command=self.encrypt).pack(side="left", padx=4)

        tk.Button(btns, text="DECRYPT", bg="#0369a1", fg="white",
                  font=FONT, width=13, relief="flat",
                  command=self.decrypt).pack(side="left", padx=4)

        tk.Button(btns, text="CLEAR", bg="#374151", fg=TEXT,
                  font=FONT, width=8, relief="flat",
                  command=self.clear_output).pack(side="left", padx=4)

        # Output console
        tk.Label(body, text="▸ OUTPUT CONSOLE",
                 fg=BLUE, bg=BG, font=FONT).pack(anchor="w", pady=(8, 2))
        self.output = tk.Text(body, height=8, bg="#000000", fg=GREEN,
                              font=FONT, relief="flat", state="normal")
        self.output.pack(fill="x")

        # DB record counter
        self.db_label = tk.Label(
            body,
            text=f"📦 Total records in DB: {self.manager.get_db_record_count()}",
            fg=GOLD, bg=BG, font=SMALL)
        self.db_label.pack(anchor="e", pady=(4, 0))

    def _build_history_panel(self, root):
        """Bottom panel: scrollable session history from linked list."""
        hist_frame = tk.Frame(root, bg=PANEL)
        hist_frame.pack(fill="both", expand=True, padx=20, pady=(8, 12))

        tk.Label(hist_frame, text="▸ SESSION HISTORY  (LinkedList + SQLite)",
                 fg=GOLD, bg=PANEL, font=FONT).pack(anchor="w", padx=8, pady=4)

        self.history_box = scrolledtext.ScrolledText(
            hist_frame, height=6, bg="#0d1117", fg="#94a3b8",
            font=SMALL, relief="flat", state="disabled")
        self.history_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # ── Callbacks ───────────────────────────────────────────────────────────
    def set_algo(self, algo):
        """Switch active algorithm and update button highlights."""
        self.algorithm = algo
        if algo == "CAESAR":
            self.caesar_btn.config(bg=GREEN, fg="black")
            self.xor_btn.config(bg=PANEL, fg=BLUE)
        else:
            self.xor_btn.config(bg=BLUE, fg="black")
            self.caesar_btn.config(bg=PANEL, fg=GREEN)
        self._write_output(f"> Algorithm switched to: {algo}\n")

    def check_key_strength(self, event=None):
        """Update key strength label and status bar on every keystroke."""
        length = len(self.key.get())
        if length >= 5:
            self.key_strength.config(text="Key Strength: STRONG ██████", fg=GREEN)
            self.status.config(text="🔒 STATUS: SECURE", fg=GREEN)
        elif length >= 3:
            self.key_strength.config(text="Key Strength: MEDIUM ████░░", fg=BLUE)
            self.status.config(text="⚠  STATUS: CHECK", fg=BLUE)
        else:
            self.key_strength.config(text="Key Strength: WEAK   ██░░░░", fg=RED)
            self.status.config(text="⚠  STATUS: INSECURE", fg=RED)

    def encrypt(self):
        """Validate inputs, call manager.encrypt(), animate output."""
        text = self.msg.get("1.0", "end").strip()
        key  = self.key.get().strip()
        if not text:
            self._write_output("> ERROR: Message field is empty.\n"); return
        if not key:
            self._write_output("> ERROR: Key field is empty.\n"); return
        try:
            result = self.manager.encrypt(self.algorithm, text, key)
            self.animate_output(
                f"> Encrypted ({self.algorithm}): {result}\n")
            self._update_db_label()
            self._refresh_history_display()
        except (ValueError, IndexError) as e:
            self._write_output(f"> ERROR: {e}\n")

    def decrypt(self):
        """Validate inputs, call manager.decrypt(), animate output."""
        text = self.msg.get("1.0", "end").strip()
        key  = self.key.get().strip()
        if not text:
            self._write_output("> ERROR: Message field is empty.\n"); return
        if not key:
            self._write_output("> ERROR: Key field is empty.\n"); return
        try:
            result = self.manager.decrypt(self.algorithm, text, key)
            self.animate_output(
                f"> Decrypted ({self.algorithm}): {result}\n")
            self._update_db_label()
            self._refresh_history_display()
        except (ValueError, IndexError) as e:
            self._write_output(f"> ERROR: {e}\n")

    def clear_output(self):
        """Clear the output console."""
        self.output.config(state="normal")
        self.output.delete("1.0", "end")
        self.output.config(state="normal")

    def animate_output(self, text, i=0):
        """Write text character-by-character at 20ms intervals (non-blocking)."""
        if i == 0:
            self.output.config(state="normal")
            self.output.delete("1.0", "end")
        if i < len(text):
            self.output.insert("end", text[i])
            self.output.see("end")
            self.output.after(20, self.animate_output, text, i + 1)

    # ── Helpers ─────────────────────────────────────────────────────────────
    def _write_output(self, text):
        """Write text directly to output console (no animation)."""
        self.output.config(state="normal")
        self.output.insert("end", text)
        self.output.see("end")

    def _update_db_label(self):
        """Refresh the SQLite record count label."""
        count = self.manager.get_db_record_count()
        self.db_label.config(
            text=f"📦 Total records in DB: {count}")

    def _refresh_history_display(self):
        """Repopulate the history ScrolledText from the linked list."""
        records = self.manager.get_history()
        self.history_box.config(state="normal")
        self.history_box.delete("1.0", "end")
        for r in reversed(records):          # newest first
            line = (f"[{r.get('timestamp', '—')}]  "
                    f"{r['algorithm']:7s}  {r.get('operation',''):7s}  "
                    f"{r['original'][:30]:30s}  →  {r['result'][:30]}\n")
            self.history_box.insert("end", line)
        self.history_box.config(state="disabled")


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    root = tk.Tk()
    EncryptionGUI(root)
    root.mainloop()
