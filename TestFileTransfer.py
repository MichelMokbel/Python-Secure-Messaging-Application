import unittest
import os
import shutil
import tempfile
from secure_messaging import *
from Crypto.PublicKey import RSA

class TestFileTransfer(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for testing file transfers
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        # Remove the temporary directory after the test
        shutil.rmtree(self.test_dir)

    def test_encrypt_and_decrypt_file(self):
        # Test if a file can be encrypted and decrypted correctly
        test_file_path = os.path.join(self.test_dir, "test_file.txt")
        encrypted_file_path = os.path.join(self.test_dir, "encrypted_file.txt")
        decrypted_file_path = os.path.join(self.test_dir, "decrypted_file.txt")

        with open(test_file_path, "w") as f:
            f.write("This is a test file.")

        private_key, public_key = generate_rsa_key_pair()

        encrypt_file(test_file_path, encrypted_file_path, public_key)
        decrypt_file(encrypted_file_path, decrypted_file_path, private_key)

        with open(test_file_path, "r") as f:
            original_content = f.read()

        with open(decrypted_file_path, "r") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_send_and_receive_file(self):
        # Test if a file can be sent and received correctly
        test_file_path = os.path.join(self.test_dir, "test_file.txt")
        received_file_path = os.path.join(self.test_dir, "received_file.txt")

        with open(test_file_path, "w") as f:
            f.write("This is a test file.")

        sender_private_key, sender_public_key = generate_rsa_key_pair()
        recipient_private_key, recipient_public_key = generate_rsa_key_pair()

        encrypted_payload = send_file(test_file_path, recipient_public_key)
        receive_file(encrypted_payload, received_file_path, recipient_private_key)

        with open(test_file_path, "r") as f:
            original_content = f.read()

        with open(received_file_path, "r") as f:
            received_content = f.read()

        self.assertEqual(original_content, received_content)

if __name__ == '__main__':
    unittest.main()
