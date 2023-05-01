import sqlite3
from user import User
from Crypto.PublicKey import RSA


class Database:
    """
    This class handles the interaction with the SQLite database.
    Attributes:
        db_name (str): The name of the SQLite database file.
    """

    def __init__(self, db_name="secure_messaging.db"):
        # Initialize the database name
        self.db_name = db_name
        # Create the necessary tables in the database
        self.create_tables()

    def get_connection(self):
        """
        Returns a connection to the SQLite database
        :return:
            sqlite3.Connection: A connection to the SQLite database

        """
        return sqlite3.connect(self.db_name)

    def create_tables(self):
        """
        Creates the necessary tables in the SQLite database (users, messages)
        """
        # Open a connection to the database
        with self.get_connection() as conn:
            # Create the users table with columns for username, password, private key, and public key
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    private_key BLOB NOT NULL,
                    public_key BLOB NOT NULL
                )
            """)
            # Create the messages table with columns for ID, sender, recipient, and encrypted payload
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL
                )
            """)

    def add_user(self, user):
        """
        Adds a new user ot the 'users' tables in the database.
        :param user: The user object to be added to the database.
        """
        # Get a connection to the database
        with self.get_connection() as conn:
            # Insert a new user into the users table with the provided values
            conn.execute("""
                INSERT INTO users (username, password, private_key, public_key) 
                VALUES (?, ?, ?, ?)
            """, (user.username, user.password, user.private_key.export_key(), user.public_key.export_key()))
            # Commit the changes to the database
            conn.commit()

    def get_user(self, username, password=None):
        """
        Retrieves a user from the 'users' table in the database.

        :param username: The username of the user to retrieve.
        :param password: The password of the user to retrieve. If provided
        the user must have the correct password to be retrieved
        :return: User: The retrieved user object, or None if the user was not found
                       or the password was incorrect
        """
        # Open a connection to the database
        with self.get_connection() as conn:
            # If a password is provided, retrieve the user with the given username and password
            if password:
                query = "SELECT username, password, private_key, public_key " \
                        "FROM users " \
                        "WHERE username = ? AND password = ?"
                cursor = conn.execute(query, (username, password))
            # Otherwise, retrieve the user with the given username
            else:
                query = "SELECT username, password, private_key, public_key FROM users WHERE username = ?"
                cursor = conn.execute(query, (username,))
            # Fetch the first result from the query
            result = cursor.fetchone()
            # If a result is found, create a User object with the retrieved information and return it
            if result:
                return User(result[0], result[1], RSA.import_key(result[2]), RSA.import_key(result[3]))
            # If no result is found, return None
            else:
                return None

    def add_message(self, sender, recipient, encrypted_payload):
        """
        Adds a new message to the 'messages' table in the database.
        :param sender: The username of the sender of the message.
        :param recipient: The username of the recipient of the message.
        :param encrypted_payload: The encrypted payload of the message.
        """
        # Get a connection to the database
        with self.get_connection() as conn:
            # Insert a new message into the messages table with the provided values
            conn.execute("""
                INSERT INTO messages (sender, recipient, encrypted_payload) VALUES (?, ?, ?)
            """, (sender, recipient, encrypted_payload))
            # Commit the changes to the database
            conn.commit()

    def get_messages_for_user(self, username):
        """
        Retrieves all messages for a specific user from the 'messages' table in the database
        :param username: The username of the user to retrieve messages for.
        :returns:
            list: A list of tuples containing the sender, recipients, and encrypted_payload of each message.
        """
        # Get a connection to the database
        with self.get_connection() as conn:
            # Execute a SELECT query to retrieve all messages for the given user
            query = "SELECT sender, recipient, encrypted_payload FROM messages WHERE recipient = ?"
            # Pass the username as a parameter to the query and execute it
            cursor = conn.execute(query, (username,))
            # Return all rows returned by the query as a list of tuples
            return cursor.fetchall()

    def get_public_key(self, username):
        """
        Retrieves the public key of a user from the 'users' table in the database.
        :param username: The username of the user to retrieve the public key for.
        :return: RSA key object representing the public key or None if the user was not found
        """
        # Open a connection to the database
        with self.get_connection() as conn:
            # Execute a SELECT query to retrieve the public key for the given user
            query = "SELECT public_key FROM users WHERE username = ?"
            # Pass the username as a parameter to the query and execute it
            cursor = conn.execute(query, (username,))
            # Fetch the first result from the query
            result = cursor.fetchone()
            # If a result is found, return the RSA public key
            if result:
                return RSA.import_key(result[0])
            # If no result is found, return None
            else:
                return None
