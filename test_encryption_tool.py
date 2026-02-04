import unittest

class TestCaesarCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = CaesarCipher()

    def test_caesar_encrypt_basic(self):
        self.assertEqual(self.cipher.encrypt("ABC", 3), "DEF")

    def test_caesar_decrypt_basic(self):
        encrypted = self.cipher.encrypt("HELLO", 5)
        self.assertEqual(self.cipher.decrypt(encrypted, 5), "HELLO")

    def test_caesar_wrap_around(self):
        self.assertEqual(self.cipher.encrypt("XYZ", 3), "ABC")

    def test_caesar_lowercase(self):
        self.assertEqual(self.cipher.encrypt("abc", 2), "cde")

    def test_caesar_with_spaces(self):
        self.assertEqual(self.cipher.encrypt("HELLO WORLD", 1), "IFMMP XPSME")

    def test_caesar_with_numbers(self):
        self.assertEqual(self.cipher.encrypt("A1B2", 1), "B1C2")


class TestXorCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = XorCipher()

    def test_xor_encrypt_decrypt(self):
        encrypted = self.cipher.encrypt("SECRET", "key")
        decrypted = self.cipher.decrypt(encrypted, "key")
        self.assertEqual(decrypted, "SECRET")

    def test_xor_same_text_same_key(self):
        encrypted1 = self.cipher.encrypt("DATA", "k")
        encrypted2 = self.cipher.encrypt("DATA", "k")
        self.assertEqual(encrypted1, encrypted2)

    def test_xor_different_key(self):
        encrypted1 = self.cipher.encrypt("DATA", "a")
        encrypted2 = self.cipher.encrypt("DATA", "b")
        self.assertNotEqual(encrypted1, encrypted2)

    def test_xor_empty_string(self):
        self.assertEqual(self.cipher.encrypt("", "key"), "")


class TestLinkedList(unittest.TestCase):
    def setUp(self):
        self.list = LinkedList()

    def test_linked_list_insert_single(self):
        self.list.insert("Test")
        self.assertEqual(self.list.traverse(), ["Test"])

    def test_linked_list_insert_multiple(self):
        self.list.insert("A")
        self.list.insert("B")
        self.list.insert("C")
        self.assertEqual(self.list.traverse(), ["A", "B", "C"])

    def test_linked_list_empty(self):
        self.assertEqual(self.list.traverse(), [])


class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.manager = EncryptionManager()

    def test_manager_encrypt_caesar(self):
        result = self.manager.encrypt("CAESAR", "HELLO", 3)
        self.assertEqual(result, "KHOOR")

    def test_manager_decrypt_caesar(self):
        encrypted = self.manager.encrypt("CAESAR", "TEST", 2)
        decrypted = self.manager.decrypt("CAESAR", encrypted, 2)
        self.assertEqual(decrypted, "TEST")

    def test_manager_encrypt_xor(self):
        result = self.manager.encrypt("XOR", "DATA", "k")
        self.assertNotEqual(result, "DATA")

    def test_history_recorded(self):
        self.manager.encrypt("CAESAR", "ONE", 1)
        self.manager.encrypt("XOR", "TWO", "k")
        history = self.manager.get_history()
        self.assertEqual(len(history), 2)

    def test_history_content(self):
        self.manager.encrypt("CAESAR", "ABC", 1)
        history = self.manager.get_history()
        self.assertEqual(history[0]["algorithm"], "CAESAR")

if __name__ == "__main__":
    unittest.main()
