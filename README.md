# mochapass

## a cli local password manager made in python

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

```plaintext
         #  #      #
        #    #      #
       #      #    #
        #    #    #
         #    #    #
          #    #  #
         #    #  #
    ####################
    #                  #
    #                  #
     #    -------0    #
     #    | | | |     #
      #              #
      #              #
       ##############
```

MochaPass is a CLI local password manager made in Python.

### Installation

Git clone, run `pip install -r requirements.txt`, then run `python3 main.py setup` in your shell (or `python main.py setup` (or `py main.py setup` (man idk)))

If you don't know what Git or Python are, something like MochaPass probably isn't for you anyway?

### Updating

Run `git pull origin` to update MochaPass.

Run `pip install --upgrade bcrypt cryptography pyotp pyperclip qrcode tercol` to update the dependencies.

### Uninstallation

Just delete the main.py file. If you wanna remove all of your data go to your home directory (somewhere at `C:\Users` if you're on Windows, for example `C:\Users\user`. if you're on MacOS get off MacOS what the hell are you doing) and delete the `mochapass` file. **Beware all of your passwords will be lost if you don't move them all somewhere before doing this.**

### Why should I use this over other password managers?

1. There's a soggy cat easter egg.
2. ...soggy cat easter egg?
3. soggy cat is surely enough to get people, right?
4. i mean... soggy cat...

### I forgot my master password, how do I reset it?

All of your passwords are gone forever idk how else to break the news to you

(you can try writing your master password on some paper or something)

### Is this really secure?

I don't know! That's the fun part!

### I wanna contribute!

Open a pull request and please please please please please use [black](https://github.com/psf/black)
