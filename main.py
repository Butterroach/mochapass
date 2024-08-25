"""
    MochaPass: a CLI local password manager
    Copyright (C) 2024  Butterroach

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import base64
import bcrypt
import getpass
import hashlib
import os
import pyotp
import pyperclip
import qrcode
import qrcode.constants
import qrcode.image.base
import qrcode.image.svg
import qrcode.main
import secrets
import sys
import tercol
import webbrowser
from cryptography.fernet import Fernet
from typing import Optional, Tuple

__version__ = "1.0.0"
SEPARATOR = ";';';.;"
ACCOUNT_DATA_SEPARATOR = ":..:.::."


def master_password_to_fernet_key(master_password: str) -> bytes:
    """
    Helper function that converts the master password provided (can actually be any string) to a key that is able to be used with Fernet.
    """
    return base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())


def decrypt_database() -> Tuple[bytes, str]:
    """
    Helper function that decrypts the MochaPass database and returns a tuple with the decrypted data as bytes and the master password provided by the user as str. It *does* ask for user input! It asks for the 2FA code, but that's not really needed to actually get data.

    WARNING: THIS WILL QUIT THE PROGRAM IF THE USER TYPES IN THE INCORRECT PASSWORD TOO MANY TIMES
    """
    file = os.path.expanduser("~/mochapass")
    if not os.path.exists(file):
        raise FileNotFoundError("mochapass database (at ~/mochapass) doesn't exist")
    with open(file, "rb") as f:
        file_parts = f.read().decode().split(SEPARATOR)
        attempts = 0
        brute_attempts = 0
        master_password_hash = file_parts[0].encode()
        while attempts < 5:
            if attempts == 4:
                while brute_attempts < 2:
                    code = hex(secrets.randbits(64))[2:8]
                    print(
                        f"Please type in the following sequence of hexadecimal digits to confirm you are not an automated bruteforcer: {code}"
                    )
                    if getpass.getpass("") == code:
                        break
                    print("Wrong! Try again.")
                    brute_attempts += 1
                if brute_attempts == 2:
                    break
            master_password = getpass.getpass("Please type in the master password: ")
            if bcrypt.checkpw(master_password.encode(), master_password_hash):
                break
            print("Wrong! Try again.")
            attempts += 1
        if attempts == 5 or brute_attempts == 2:
            print("Too many incorrect attempts. Exiting.")
            print(
                "If you forgot your password uhhh I hate to break it to you but there ain't no resetting your master password all your passwords are gone forever man I don't know how to break the news to you I'm sorry"
            )
            print(
                "(if you setup mochapass all over again please try writing the master password on some paper)"
            )
            sys.exit(1)
        cipher = Fernet(master_password_to_fernet_key(master_password))
        decrypted_data = cipher.decrypt(file_parts[1].encode())
        decrypted_data_parts = decrypted_data.decode().split(SEPARATOR)
        secret_key = decrypted_data_parts[0]
        totp = pyotp.totp.TOTP(secret_key)
        while True:
            user_otp = input("2FA code from the authenticator app: ")
            if totp.verify(user_otp):
                break
            print("Wrong. Try again.")
        return decrypted_data, master_password


def write_to_database(new_data: bytes, master_password: Optional[str] = None) -> None:
    """
    Helper function that overwrites the original encrypted data of the database with the new provided data. Uses decrypt_database() to get the master password if master_password is not provided as an argument.
    """
    if master_password is None:
        master_password = decrypt_database()[
            1
        ]  # we don't care about the data, only the master password
    file = os.path.expanduser("~/mochapass")
    if not os.path.exists(file):
        raise FileNotFoundError("mochapass database (at ~/mochapass) doesn't exist")
    with open(file, "rb") as f:
        contents: bytes = f.read()
    with open(file, "wb") as f:
        cipher = Fernet(master_password_to_fernet_key(master_password))
        f.write(
            contents.split(SEPARATOR.encode())[0]
            + SEPARATOR.encode()
            + cipher.encrypt(new_data)
        )


def make(args: argparse.Namespace):
    if args.id.casefold() == "love":
        print("not war?")
    if " " in args.id:
        print("do you really want spaces in your id..?")
    if any((SEPARATOR in args.id, ACCOUNT_DATA_SEPARATOR in args.id)):
        print(
            f"ERROR! Please do NOT include the sequence of symbols of either {SEPARATOR} or {ACCOUNT_DATA_SEPARATOR} in your password!"
        )
        print(
            "This is due to how the database works. It uses those seperators. If you include those the database will break and the account with one of those sequences will no longer be accessible."
        )
        print("...why do you want those sequences in an account id anyway? :P")
        sys.exit(1)
    if args.id == "soggy_cat":
        print("That's reserved for a special easter egg! Please use another ID.")
        sys.exit(1)
    password = SEPARATOR
    no_password_yet = True
    decrypted_data, master_password = decrypt_database()
    if any(
        (
            [
                i.split(ACCOUNT_DATA_SEPARATOR)[0] == args.id
                for i in decrypted_data.decode().split(SEPARATOR)[1:]
            ]
        )
    ):
        print("The ID must be unique!")
        print(
            "This *only* appeared now because this check can only be made after the data is decrypted, and the master password was needed to decrypt the data. Sorry for the inconvenience."
        )
        sys.exit(1)
    while any((SEPARATOR in password, ACCOUNT_DATA_SEPARATOR in password)):
        if not no_password_yet and not args.generate:
            print(
                f"ERROR! Please do NOT include the sequence of symbols of either {SEPARATOR} or {ACCOUNT_DATA_SEPARATOR} in your password!"
            )
            print(
                "This is due to how the database works. It uses those seperators. If you include those the database will break and the account with one of those sequences will no longer be accessible."
            )
        if not args.generate:
            password = getpass.getpass(
                f"Enter the password you wanna use for {args.id}: "
            )
        else:
            password = "".join(
                [
                    secrets.choice(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+"
                    )
                    for _ in range(args.generate)
                ]
            )
            # ^ what a mouthful!
        no_password_yet = False
    write_to_database(
        (
            decrypted_data.decode()
            + SEPARATOR
            + args.id
            + ACCOUNT_DATA_SEPARATOR
            + password
        ).encode(),
        master_password,
    )
    print("Done!")


def get(args):
    if args.id == "soggy_cat":
        webbrowser.open("https://soggy.cat/img/soggycat.webp")
        sys.exit(0)
    decrypted_data, _ = decrypt_database()
    accounts = decrypted_data.decode().split(SEPARATOR)[1:]
    try:
        account_index = [
            i.split(ACCOUNT_DATA_SEPARATOR)[0] == args.id for i in accounts
        ].index(True)
    except ValueError:
        print(
            "That account doesn't exist. Maybe you made a typo or something? Beware this is case sensitive."
        )
        sys.exit(0)
    pyperclip.copy(accounts[account_index].split(ACCOUNT_DATA_SEPARATOR)[1])
    print("Done! Password copied to clipboard.")


def list_accs(args):
    decrypted_data, _ = decrypt_database()
    print("Every single account ID you currently have:")
    for acc in decrypted_data.decode().split(SEPARATOR)[1:]:
        print(acc.split(ACCOUNT_DATA_SEPARATOR)[0])


def setup(args):
    file = os.path.normpath(os.path.expanduser("~/mochapass"))
    if os.path.exists(file):
        print(
            tercol.red(
                f"You already setup MochaPass! Delete {file} then run this again if you REALLY wanna set it up all over again, but beware that you're gonna lose all of your passwords that you saved into MochaPass if you do that."
            )
        )
        return
    with open(file, "wb") as f:
        secret_key = pyotp.random_base32()
        totp = pyotp.totp.TOTP(secret_key)
        totp_uri = totp.provisioning_uri(issuer_name="MochaPass").encode()
        master_password = ""
        password_written_again = " "
        while True:
            master_password = getpass.getpass(
                "Enter the master password (don't forget!): "
            )
            if len(master_password) < 10:
                print("Please make your password 10 chars long.")
                continue
            if all([not c in master_password for c in "0123456789"]):
                print("Please include numbers into the password.")
                continue
            if all([not c in master_password for c in "!@#$%^&*()"]):
                print("Please include special characters into the password.")
                continue
            password_written_again = getpass.getpass("Enter it again: ")
            if master_password == password_written_again:
                break
            print("The passwords do not match. Try again.")
        f.write(bcrypt.hashpw(master_password.encode(), bcrypt.gensalt()))
        cipher = Fernet(
            base64.urlsafe_b64encode(hashlib.sha256(master_password.encode()).digest())
        )
        qr = qrcode.main.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
        print("Scan the above QR code with an authenticator app on your smartphone.")
        print(
            "Alternatively, if the QR code doesn't work, try manually typing this code instead:"
        )
        print(secret_key)
        print("Once you're done: ", end="")
        while True:
            user_totp = input(
                "Get the one-time code from the authenticator and enter it here: "
            )
            if totp.verify(user_totp):
                f.write(SEPARATOR.encode() + cipher.encrypt(secret_key.encode()))
                print("MochaPass has finished setting up.")
                break
            else:
                print(tercol.red("Wrong code! Try again."))


parser = argparse.ArgumentParser(
    description="A CLI local password manager.",
)
subparsers = parser.add_subparsers(dest="command", title="actions")
parser_make = subparsers.add_parser("make", help="add a new account")
parser_make.add_argument(
    "-i",
    "--id",
    help="the id for the account you want to add, the id should be unique",
    required=True,
)
parser_make.add_argument(
    "--generate",
    "-g",
    help="generate a password for the account of specified character length",
    type=int,
    required=False,
)
parser_make.set_defaults(func=make)
parser_get = subparsers.add_parser(
    "get", help="get the password for the account with the specific ID provided"
)
parser_get.add_argument(
    "--id", help="the id for the account you want to get the password of", required=True
)
parser_get.set_defaults(func=get)
parser_list = subparsers.add_parser("list", help="list all account ids available")
parser_list.set_defaults(func=list_accs)
parser_setup = subparsers.add_parser("setup", help="sets up mochapass")
parser_setup.set_defaults(func=setup, setup=True)
args = parser.parse_args()

if hasattr(args, "func"):
    if not os.path.exists(os.path.expanduser("~/mochapass")) and not hasattr(
        args, "setup"
    ):
        print(
            tercol.red("Looks like MochaPass hasn't been set up yet!"),
            "Please run the following to start setting up MochaPass:\n",
            f"\t{os.path.normpath(sys.executable).split('/')[-1].split(chr(92))[-1]} {__file__} setup",
        )
    else:
        args.func(args)
else:
    print(
        f"""
{tercol.gray('''
         #  #      #
        #    #      #
       #      #    #
        #    #    #
         #    #    #
          #    #  #
         #    #  #''')}
    {tercol.hexa(0x884e3f,'''####################
    #                  #
    #                  #''')}
     {tercol.hexa(0x884e3f,"#")}    {tercol.yellow("-------0")}    {tercol.hexa(0x884e3f,"#")}
     {tercol.hexa(0x884e3f,"#")}    {tercol.yellow("| | | |")}     {tercol.hexa(0x884e3f,"#")}
      {tercol.hexa(0x884e3f,'''#      	     #
      #              #
       ##############''')}
    {tercol.hexa(0xd57962,tercol.bold("mocha"))}{tercol.yellow("pass")} - v{__version__}
        """
    )
    print("Run --help for more info on how to use MochaPass.")
    print("MochaPass is licensed under the GNU GPL-v3.")
