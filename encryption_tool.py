import tkinter as tk
from abc import ABC, abstractmethod

BG = "#0b0f14"
PANEL = "#111827"
GREEN = "#00ff9c"
BLUE = "#38bdf8"
RED = "#f43f5e"
TEXT = "#e5e7eb"

FONT = ("Consolas", 11)
TITLE = ("Consolas", 16, "bold")


class Node:
    def __init__(self, data):
        self.data = data
        self.next = None


class LinkedList:
    def __init__(self):
        self.head = None

    def insert(self, data):
        new_node = Node(data)
        if not self.head:
            self.head = new_node
            return
        current = self.head
        while current.next:
            current = current.next
        current.next = new_node

    def traverse(self):
        items = []
        current = self.head
        while current:
            items.append(current.data)
            current = current.next
        return items



class Cipher(ABC):
    @abstractmethod
    def encrypt(self, plaintext, key):
        pass

    @abstractmethod
    def decrypt(self, ciphertext, key):
        pass



class CaesarCipher(Cipher):
    def encrypt(self, plaintext, key):
        result = ""
        shift = int(key)

        for char in plaintext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result

    def decrypt(self, ciphertext, key):
        return self.encrypt(ciphertext, -int(key))



class XorCipher(Cipher):
    def encrypt(self, plaintext, key):
        result = ""
        for i, char in enumerate(plaintext):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result

    def decrypt(self, ciphertext, key):
        return self.encrypt(ciphertext, key)


class EncryptionManager:
    def __init__(self):
        self.history = LinkedList()
        self.ciphers = {
            "CAESAR": CaesarCipher(),
            "XOR": XorCipher()
        }

    def encrypt(self, algorithm, message, key):
        cipher = self.ciphers[algorithm]
        encrypted = cipher.encrypt(message, key)
        self.history.insert({
            "algorithm": algorithm,
            "original": message,
            "result": encrypted
        })
        return encrypted

    def decrypt(self, algorithm, message, key):
        cipher = self.ciphers[algorithm]
        return cipher.decrypt(message, key)

    def get_history(self):
        return self.history.traverse()



class EncryptionGUI:
    def __init__(self, root):
        self.manager = EncryptionManager()
        self.algorithm = "CAESAR"

        root.title("CYBER VAULT :: ENCRYPTION LAB")
        root.geometry("900x600")
        root.configure(bg=BG)
        root.resizable(False, False)

     
        header = tk.Frame(root, bg=PANEL, height=60)
        header.pack(fill="x")
        tk.Label(header, text="CYBER VAULT :: ENCRYPTION LAB",
                 fg=GREEN, bg=PANEL, font=TITLE).pack(side="left", padx=20)

        self.status = tk.Label(header, text="🔒 STATUS: SECURE",
                               fg=GREEN, bg=PANEL, font=FONT)
        self.status.pack(side="right", padx=20)

      
        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=20)

    
        tk.Label(body, text="MESSAGE INPUT", fg=BLUE, bg=BG).pack(anchor="w")
        self.msg = tk.Text(body, height=4, bg=PANEL, fg=TEXT)
        self.msg.pack(fill="x")

      
        tk.Label(body, text="KEY", fg=BLUE, bg=BG).pack(anchor="w", pady=(10, 0))
        self.key = tk.Entry(body, bg=PANEL, fg=TEXT)
        self.key.pack(fill="x")
        self.key.bind("<KeyRelease>", self.check_key_strength)

        self.key_strength = tk.Label(body, text="Key Strength: UNKNOWN",
                                     fg=RED, bg=BG, font=FONT)
        self.key_strength.pack(anchor="w", pady=5)

    
        btns = tk.Frame(body, bg=BG)
        btns.pack(pady=15)

        tk.Button(btns, text="CAESAR", bg=GREEN, width=12,
                  command=lambda: self.set_algo("CAESAR")).pack(side="left", padx=5)
        tk.Button(btns, text="XOR", bg=BLUE, width=12,
                  command=lambda: self.set_algo("XOR")).pack(side="left", padx=5)
        tk.Button(btns, text="ENCRYPT", width=12,
                  command=self.encrypt).pack(side="left", padx=5)
        tk.Button(btns, text="DECRYPT", width=12,
                  command=self.decrypt).pack(side="left", padx=5)

       
        tk.Label(body, text="OUTPUT CONSOLE", fg=BLUE, bg=BG).pack(anchor="w")
        self.output = tk.Text(body, height=10, bg="black", fg=GREEN)
        self.output.pack(fill="both", expand=True)

 
    def set_algo(self, algo):
        self.algorithm = algo
        self.output.insert("end", f"> Algorithm set to {algo}\n")
        self.output.see("end")

    def check_key_strength(self, event=None):
        length = len(self.key.get())
        if length >= 5:
            self.key_strength.config(text="Key Strength: STRONG", fg=GREEN)
            self.status.config(text="🔒 STATUS: SECURE", fg=GREEN)
        elif length >= 3:
            self.key_strength.config(text="Key Strength: MEDIUM", fg=BLUE)
            self.status.config(text="🔒 STATUS: CHECK", fg=BLUE)
        else:
            self.key_strength.config(text="Key Strength: WEAK", fg=RED)
            self.status.config(text="⚠ STATUS: INSECURE", fg=RED)

    def encrypt(self):
        text = self.msg.get("1.0", "end").strip()
        key = self.key.get()
        if not text or not key:
            return
        result = self.manager.encrypt(self.algorithm, text, key)
        self.animate_output(f"> Encrypted ({self.algorithm}): {result}\n")

    def decrypt(self):
        text = self.msg.get("1.0", "end").strip()
        key = self.key.get()
        if not text or not key:
            return
        result = self.manager.decrypt(self.algorithm, text, key)
        self.animate_output(f"> Decrypted ({self.algorithm}): {result}\n")

    def animate_output(self, text, i=0):
        if i == 0:
            self.output.delete("1.0", "end")
        if i < len(text):
            self.output.insert("end", text[i])
            self.output.see("end")
            self.output.after(25, self.animate_output, text, i + 1)

if __name__ == "__main__":
    root = tk.Tk()
    EncryptionGUI(root)
    root.mainloop()
