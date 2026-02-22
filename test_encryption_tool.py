import unittest
import os
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock

from encryption_decryption import (
    CaesarCipher, XorCipher, LinkedList, Node,
    EncryptionManager, PersistenceManager
)


# ════════════════════════════════════════════════════════════════════════════
class TestCaesarCipher(unittest.TestCase):
    """Unit tests for CaesarCipher — 6 tests."""

    def setUp(self):
        self.cipher = CaesarCipher()

    def test_caesar_encrypt_basic(self):
        """Standard shift: ABC + 3 = DEF."""
        self.assertEqual(self.cipher.encrypt("ABC", 3), "DEF")

    def test_caesar_decrypt_basic(self):
        """Round-trip: encrypt then decrypt recovers original."""
        encrypted = self.cipher.encrypt("HELLO", 5)
        self.assertEqual(self.cipher.decrypt(encrypted, 5), "HELLO")

    def test_caesar_wrap_around(self):
        """Alphabet wrap: XYZ + 3 = ABC."""
        self.assertEqual(self.cipher.encrypt("XYZ", 3), "ABC")

    def test_caesar_lowercase(self):
        """Lowercase preserved: abc + 2 = cde."""
        self.assertEqual(self.cipher.encrypt("abc", 2), "cde")

    def test_caesar_with_spaces(self):
        """Non-alpha chars (spaces) preserved unchanged."""
        self.assertEqual(self.cipher.encrypt("HELLO WORLD", 1), "IFMMP XPSME")

    def test_caesar_with_numbers(self):
        """Digits preserved unchanged."""
        self.assertEqual(self.cipher.encrypt("A1B2", 1), "B1C2")


# ════════════════════════════════════════════════════════════════════════════
class TestXorCipher(unittest.TestCase):
    """Unit tests for XorCipher — 4 tests."""

    def setUp(self):
        self.cipher = XorCipher()

    def test_xor_encrypt_decrypt(self):
        """XOR involution: encrypt then decrypt with same key = original."""
        encrypted = self.cipher.encrypt("SECRET", "key")
        decrypted = self.cipher.decrypt(encrypted, "key")
        self.assertEqual(decrypted, "SECRET")

    def test_xor_same_text_same_key(self):
        """Deterministic: identical inputs produce identical ciphertext."""
        enc1 = self.cipher.encrypt("DATA", "k")
        enc2 = self.cipher.encrypt("DATA", "k")
        self.assertEqual(enc1, enc2)

    def test_xor_different_key(self):
        """Different keys produce different ciphertext."""
        enc1 = self.cipher.encrypt("DATA", "a")
        enc2 = self.cipher.encrypt("DATA", "b")
        self.assertNotEqual(enc1, enc2)

    def test_xor_empty_string(self):
        """Empty string input returns empty string output."""
        self.assertEqual(self.cipher.encrypt("", "key"), "")


# ════════════════════════════════════════════════════════════════════════════
class TestLinkedList(unittest.TestCase):
    """Unit tests for custom Node / LinkedList — 5 tests."""

    def setUp(self):
        self.ll = LinkedList()

    def test_linked_list_insert_single(self):
        """Single insert: traverse returns one-element list."""
        self.ll.insert("Test")
        self.assertEqual(self.ll.traverse(), ["Test"])

    def test_linked_list_insert_multiple(self):
        """Multiple inserts: insertion order is preserved."""
        self.ll.insert("A")
        self.ll.insert("B")
        self.ll.insert("C")
        self.assertEqual(self.ll.traverse(), ["A", "B", "C"])

    def test_linked_list_empty(self):
        """Empty list: traverse returns empty list."""
        self.assertEqual(self.ll.traverse(), [])

    def test_linked_list_size_counter(self):
        """Size counter increments correctly on each insert."""
        self.ll.insert("X")
        self.ll.insert("Y")
        self.assertEqual(self.ll.size, 2)

    def test_linked_list_node_structure(self):
        """Node.next pointer is None for a single-element list."""
        self.ll.insert("only")
        self.assertIsNone(self.ll.head.next)


# ════════════════════════════════════════════════════════════════════════════
class TestPersistenceManager(unittest.TestCase):
    """Unit tests for PersistenceManager (SQLite + file) — 5 tests.

    Uses a temporary directory to avoid polluting the working directory.
    """

    def setUp(self):
        self.tmp_dir  = tempfile.mkdtemp()
        self.db_path  = os.path.join(self.tmp_dir, "test_vault.db")
        self.log_path = os.path.join(self.tmp_dir, "test_log.txt")
        self.pm       = PersistenceManager(self.db_path, self.log_path)
        self.sample   = {
            "algorithm": "CAESAR",
            "operation": "ENCRYPT",
            "original":  "HELLO",
            "result":    "KHOOR",
            "timestamp": "2026-03-01 12:00:00"
        }

    def tearDown(self):
        """Clean up temp files after each test."""
        for path in [self.db_path, self.log_path]:
            if os.path.exists(path):
                os.remove(path)

    def test_database_table_created(self):
        """Database file and table are created on PersistenceManager init."""
        self.assertTrue(os.path.exists(self.db_path))
        conn   = sqlite3.connect(self.db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        conn.close()
        table_names = [t[0] for t in tables]
        self.assertIn("encryption_history", table_names)

    def test_save_record_to_database(self):
        """save_record inserts one row into encryption_history."""
        self.pm.save_record(self.sample)
        conn  = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM encryption_history").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_save_record_to_log_file(self):
        """save_record writes a correctly formatted line to the log file."""
        self.pm.save_record(self.sample)
        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("CAESAR", content)
        self.assertIn("HELLO", content)
        self.assertIn("KHOOR", content)

    def test_load_history_returns_saved_records(self):
        """load_history retrieves previously saved records from SQLite."""
        self.pm.save_record(self.sample)
        records = self.pm.load_history()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["algorithm"], "CAESAR")
        self.assertEqual(records[0]["result"],    "KHOOR")

    def test_get_record_count(self):
        """get_record_count reflects the number of inserted records."""
        self.pm.save_record(self.sample)
        self.pm.save_record({**self.sample, "algorithm": "XOR"})
        self.assertEqual(self.pm.get_record_count(), 2)


# ════════════════════════════════════════════════════════════════════════════
class TestEncryptionManager(unittest.TestCase):
    """Unit tests for EncryptionManager — 7 tests.

    PersistenceManager is patched so tests run without touching disk.
    """

    def setUp(self):
        # Patch PersistenceManager so no real DB/file is created
        patcher = patch(
            "encryption_decryption.PersistenceManager",
            autospec=True
        )
        self.MockPM = patcher.start()
        self.addCleanup(patcher.stop)

        mock_pm_instance = self.MockPM.return_value
        mock_pm_instance.load_history.return_value = []
        mock_pm_instance.save_record.return_value  = None
        mock_pm_instance.get_record_count.return_value = 0

        self.manager = EncryptionManager()

    def test_manager_encrypt_caesar(self):
        """Correct Caesar delegation: HELLO + 3 = KHOOR."""
        result = self.manager.encrypt("CAESAR", "HELLO", 3)
        self.assertEqual(result, "KHOOR")

    def test_manager_decrypt_caesar(self):
        """Caesar round-trip via manager: encrypt then decrypt."""
        encrypted = self.manager.encrypt("CAESAR", "TEST", 2)
        decrypted = self.manager.decrypt("CAESAR", encrypted, 2)
        self.assertEqual(decrypted, "TEST")

    def test_manager_encrypt_xor(self):
        """XOR encryption changes the text."""
        result = self.manager.encrypt("XOR", "DATA", "k")
        self.assertNotEqual(result, "DATA")

    def test_manager_decrypt_xor(self):
        """XOR round-trip via manager recovers original."""
        encrypted = self.manager.encrypt("XOR", "SECRET", "key")
        decrypted = self.manager.decrypt("XOR", encrypted, "key")
        self.assertEqual(decrypted, "SECRET")

    def test_history_recorded_after_encrypt(self):
        """Linked list grows by one after each encrypt call."""
        self.manager.encrypt("CAESAR", "ONE", 1)
        self.manager.encrypt("XOR",    "TWO", "k")
        self.assertEqual(len(self.manager.get_history()), 2)

    def test_history_content_algorithm_field(self):
        """History record stores the correct algorithm name."""
        self.manager.encrypt("CAESAR", "ABC", 1)
        history = self.manager.get_history()
        self.assertEqual(history[0]["algorithm"], "CAESAR")

    def test_history_content_operation_field(self):
        """History record distinguishes ENCRYPT from DECRYPT."""
        self.manager.encrypt("CAESAR", "ABC", 1)
        self.manager.decrypt("CAESAR", "BCD", 1)
        history = self.manager.get_history()
        self.assertEqual(history[0]["operation"], "ENCRYPT")
        self.assertEqual(history[1]["operation"], "DECRYPT")


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    unittest.main(verbosity=2)
