import pandas as pd
import os
import hashlib
from cryptography.fernet import Fernet
import warnings
from art import *
import ast
import pyperclip
import random
import string


class PasswordManager:
    def __init__(self):
        self.users_data = pd.read_csv('users.csv')
        self.passwords = pd.read_csv('passwords.csv')
        self.logged_in = False
        self.username = None
        self.uuid = None

    def register(self):
        """
        Create a new user
        :return: None
        """
        print('---- Register ----')
        username = input('Enter username: ')
        pwd = input('Enter password: ')
        conf_pwd = input("Confirm password: ")

        if conf_pwd == pwd:
            enc = conf_pwd.encode()
            hash1 = hashlib.md5(enc).hexdigest()

        else:
            print('Passwords do not match')
            return self.register()

        key = Fernet.generate_key()
        self.users_data = self.users_data.append(
            {
                'uuid': key,
                'username': username,
                'password': hash1,
            },
            ignore_index=True)
        self.users_data.to_csv('users.csv', index=False)

    def login(self):
        """
        Login to the application
        :return: None
        """
        username = input('Enter username: ')
        pwd = input('Enter password: ')
        auth = pwd.encode()
        auth_hash = hashlib.md5(auth).hexdigest()

        if username in self.users_data['username'].values:
            if auth_hash == self.users_data[self.users_data['username'] == username]['password'].values[0]:
                print('Login successful!')
                self.logged_in = True
                self.username = username
                uuid = self.users_data[self.users_data['username'] == username]['uuid'].values[0]
                self.uuid = _parse_bytes(uuid)

        else:
            print('Login failed!')
            print('''
            1. Register
            2. Login again
            3. Exit
            ''')
            choice = input('Enter your choice: ')
            if choice == '1':
                return self.register()
            elif choice == '2':
                return self.login()
            return exit()

    def add_password(self):
        """
        Add a new password
        :return: None
        """
        print('---- Add New Password ----')
        website = input('Enter website: ')
        username = input('Enter username or email: ')
        rando = input('Would you like a generated a random password? (y/n): ')
        if rando == 'y':
            length = int(input('Enter length of password: '))
            pwd = generate_random(length)
        else:
            pwd = input('Enter password: ')
        uuid = self.uuid
        encrypted = Fernet(uuid).encrypt(pwd.encode()).decode()
        self.passwords = self.passwords.append(
            {
                'uuid': uuid,
                'site': website,
                'user': username,
                'password': encrypted,
            },
            ignore_index=True)
        self.passwords.to_csv('passwords.csv', index=False)
        return register(self)

    def view_passwords(self):
        """
        View all passwords
        :return: None
        """
        print('---- View All Passwords ----')
        if self.logged_in:
            df = self.passwords.loc[self.passwords['uuid'] == self.uuid]
            df['password'] = df['password'].apply(lambda x: Fernet(self.uuid).decrypt(x.encode()).decode())
            df_hashed = df.copy()
            df_hashed['password'] = '**********'
            print(df_hashed[['site', 'user', 'password']])
            c = input('Do you want to see hashed passwords? (y/n): ')
            if c == 'y':
                print('---- View All Passwords ----')
                print(df[['site', 'user', 'password']])
            return register(self)
        else:
            print('You must be logged in to view passwords!')
            return self.login()

    def view_site_password(self):
        """
        View password by site
        :return: None
        """
        print('---- View Password by Site ----')
        if self.logged_in:
            site = input('Enter website: ')
            df = self.passwords.loc[(self.passwords['site'] == site) & (self.passwords['uuid'] == self.uuid)]
            df['password'] = df['password'].apply(lambda x: Fernet(self.uuid).decrypt(x.encode()).decode())
            df_hashed = df.copy()
            df_hashed['password'] = '**********'
            print(df_hashed[['site', 'user', 'password']])
            c = input('Do you want to see hashed passwords? (y/n): ')
            if c == 'y':
                print(df[['site', 'user', 'password']])
                cop = input('Do you want to copy the password to clipboard? (y/n): ')
                if cop == 'y':
                    print('---- View Password by Site ----')
                    pyperclip.copy(df['password'].values[0])

            return register(self)
        else:
            print('You must be logged in to view passwords!')
            return self.login()

    def update_password(self):
        """
        Update password
        :return: None
        """
        print('---- Update Password ----')
        site = input('Enter website: ')
        df = self.passwords.loc[(self.passwords['site'] == site) & (self.passwords['uuid'] == self.uuid)]
        u = df['user'].values[0]
        p = df['password'].values[0]
        df['password'] = df['password'].apply(lambda x: Fernet(self.uuid).decrypt(x.encode()).decode())
        df_hashed = df.copy()
        df_hashed['password'] = '**********'
        print(df_hashed[['site', 'user', 'password']])
        user = input('Enter username or email: ')
        password = input('Enter new password: ')
        encrypted = Fernet(self.uuid).encrypt(password.encode()).decode()
        self.passwords.loc[self.passwords['password'] == p, 'password'] = encrypted
        self.passwords.loc[self.passwords['user'] == u, 'user'] = user
        self.passwords.to_csv('passwords.csv', index=False)
        print('Password updated!')
        df1 = self.passwords.loc[(self.passwords['site'] == site) & (self.passwords['uuid'] == self.uuid)]
        df1['password'] = df1['password'].apply(lambda x: Fernet(self.uuid).decrypt(x.encode()).decode())
        print(df1[['site', 'user', 'password']])
        return register(self)

    def delete_password(self):
        """
        Delete password
        :return: None
        """
        print('----- Delete Password ----')

        site = input('Enter website: ')
        df = self.passwords.loc[(self.passwords['site'] == site) & (self.passwords['uuid'] == self.uuid)]
        df['password'] = df['password'].apply(lambda x: Fernet(self.uuid).decrypt(x.encode()).decode())
        df_hashed = df.copy()
        df_hashed['password'] = '**********'
        print(df_hashed[['site', 'user', 'password']])
        c = input('Do you want to delete this password? (y/n): ')
        if c == 'y':
            self.passwords = self.passwords.drop(self.passwords[(self.passwords['site'] == site) & (self.passwords['uuid'] == self.uuid)].index)
            self.passwords.to_csv('passwords.csv', index=False)
            print('Password deleted!')
            return register(self)
        print('Password not deleted!')
        return self.view_passwords()


def generate_random(length):
    """
    Generate random string
    :param length: length of string
    :return: password
    """
    password = ''.join(random.choice(string.printable) for i in range(length))
    print("Random password is:", password)
    return password


def _parse_bytes(field):
    """Convert string represented in Python byte-string literal b'' syntax into
    a decoded character string - otherwise return it unchanged.
    """
    result = field
    try:
        result = ast.literal_eval(field)
    finally:
        return result.decode() if isinstance(result, bytes) else result


def create_csv():
    """
    Create a new csv files
    :return: None
    """
    users_exists = os.path.exists('users.csv')
    passwords_exists = os.path.exists('passwords.csv')
    if not users_exists and not passwords_exists:
        print('Creating new csv files')
        users_data = pd.DataFrame(columns=['uuid', 'username', 'password'])
        users_data.to_csv('users.csv', index=False)
        passwords_data = pd.DataFrame(columns=['uuid', 'site', 'user', 'password'])
        passwords_data.to_csv('passwords.csv', index=False)
    return None


def home():
    a = text2art('',
                 font='block',
                 chr_ignore=False,
                 )
    print(a)
    print("""
    1. Register
    2. Login
    3. Exit
    """)


def register(pm):
    print("""
    1. Add new password
    2. View passwords
    3. View site password
    4. Update password
    5. Delete password
    6. Exit
    """)
    choice = input('Enter your choice: ')
    if choice == '1':
        return pm.add_password()
    elif choice == '2':
        return pm.view_passwords()
    elif choice == '3':
        return pm.view_site_password()
    elif choice == '4':
        return pm.update_password()
    elif choice == '5':
        return pm.delete_password()
    elif choice == '6':
        return exit()
    else:
        return register(pm)


def mainMenu(pm, choice):
    if choice == '1':
        pm.register()
        print('Registration successful!')
        print('Please login to continue')
        pm.login()
        register(pm)
        return
    elif choice == '2':
        pm.login()
        register(pm)
        return
    elif choice == '3':
        exit()


def main():
    tprint('')
    warnings.simplefilter(action='ignore')

    create_csv()
    pm = PasswordManager()
    home()
    choice = input('Enter your choice: ')
    mainMenu(pm, choice)


if __name__ == '__main__':
    main()
