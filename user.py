class User:
    """
    This class represents a user in the secure messaging application
    Attributes:
        username (str): The username of the user.
        password (str): The password of the user.
        private_key (RSA key object): The user's private key
        public_key (RSA key object): The user's public key
    """

    def __init__(self, username, password, private_key, public_key):
        self.username = username
        self.password = password
        self.private_key = private_key
        self.public_key = public_key
