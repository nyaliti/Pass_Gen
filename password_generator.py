import datetime
import hashlib
import random
import string

# User database file path
USER_DB_FILE = "user_db.txt"

# Password database file path
PASSWORD_DB_FILE = "password_db.txt"


def hash_password(password):
    # Create a new SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the password
    sha256_hash.update(password.encode('utf-8'))

    # Get the hashed password
    hashed_password = sha256_hash.hexdigest()

    return hashed_password

    


def check_username_exists(username):
    """
    Check if the given username already exists in the user database file.
    Returns True if the username exists, False otherwise.
    """
    with open(USER_DB_FILE, "r") as user_db:
        for line in user_db:
            if line.startswith(username + ":"):
                return True
    return False


def register_user():
    """
    Register a new user by prompting for a unique username and password.
    Check if the username already exists in the user database file.
    If the username is unique, hash the password and save the username and hashed password to the user database file.
    """
    username = input("Enter a username: ")
    password = input("Enter a password: ")

    # Check if username already exists
    if check_username_exists(username):
        print("Username already exists. Please choose a different username.")
        return

    # Hash the password
    hashed_password = hash_password(password)

    # Save the username and hashed password to the user database file
    with open(USER_DB_FILE, "a") as user_db:
        user_db.write(f"{username}:{hashed_password}\n")

    print("User registered successfully!")



def login_user():
    """
    Log in an existing user by prompting for the username and password.
    Retrieve the hashed password from the user database file based on the provided username.
    Hash the entered password and compare it with the stored hashed password to authenticate the user.
    """
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Retrieve the hashed password from the user database file
    stored_password = hashed_password(username)

    if stored_password is None:
        print("Invalid username.")
        return

    # Hash the entered password
    hashed_user_password = hash_password(password)

    # Compare the hashed passwords
    if hashed_user_password == stored_password:
        print("Login successful!")
        return True
    else:
        print("Invalid password.")
        return False



def password_generator():
    """
    Generate a random password using the entered texts/keywords and additional random characters.
    """
    texts = input("Enter some texts or keywords to include in the password: ")
    password_length = random.randint(10, 15)  # Randomly choose a password length between 10 and 15 characters

    password = ""

    # Include the entered texts/keywords in the password
    password += texts

    # Generate additional random characters to complete the password length
    for _ in range(password_length - len(texts)):
        password += random.choice(string.ascii_letters + string.digits + string.punctuation)

    print("Generated password:", password)

    return password


def save_password(password):
    """
    Save the generated password along with the date and time of creation in a separate file in hashed format.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hashed_password = hash_password(password)

    with open(PASSWORD_DB_FILE, "a") as password_db:
        password_db.write(f"{hashed_password}:{timestamp}\n")

    print("Password saved successfully!")


def view_saved_passwords():
    """
    Read the password file and display the saved passwords along with their creation dates and times.
    """
    with open(PASSWORD_DB_FILE, "r") as password_db:
        for line in password_db:
            hashed_password, timestamp = line.strip().split(":")
            password = decrypt_password(hashed_password)
            print(f"Password: {password}\nCreated at: {timestamp}\n")


def delete_password():
    """
    Prompt the user to enter the password they want to delete.
    Remove the specified password from the password file.
    """
    password_to_delete = input("Enter the password you want to delete: ")
    hashed_password_to_delete = hash_password(password_to_delete)

    with open(PASSWORD_DB_FILE, "r") as password_db:
        lines = password_db.readlines()

    with open(PASSWORD_DB_FILE, "w") as password_db:
        for line in lines:
            if not line.startswith(hashed_password_to_delete):
                password_db.write(line)

    print("Password deleted successfully!")


def check_password_strength(password):
    """
    Check the strength of the generated password based on length and complexity.
    Returns a string indicating the password strength.
    """
    if len(password) < 8:
        return "Weak Password: Password should be at least 8 characters long"

    has_uppercase = False
    has_lowercase = False
    has_number = False
    has_special = False

    for char in password:
        if char.isupper():
            has_uppercase = True
        elif char.islower():
            has_lowercase = True
        elif char.isdigit():
            has_number = True
        else:
            has_special = True

    if not (has_uppercase and has_lowercase and has_number and has_special):
        return "Weak Password: Password should have a mix of uppercase and lowercase letters, numbers, and special characters"

    return "Strong Password"


def main():
    """
    Main program loop.
    Displays a menu with options for registration, login, password generation, viewing saved passwords, and deleting passwords.
    Based on the user's choice, calls the corresponding functions.
    """
    while True:
        print("\nPassword Generator Menu:")
        print("1. Register")
        print("2. Login")
        print("3. Generate Password")
        print("4. View Saved Passwords")
        print("5. Delete Password")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ")

        if choice == "1":
            register_user()
        elif choice == "2":
            if login_user():
                while True:
                    print("\nLogged in Menu:")
                    print("1. Change Password")
                    print("2. Generate Password")
                    print("3. View Saved Passwords")
                    print("4. Delete Password")
                    print("5. Logout")

                    logged_in_choice = input("Enter your choice (1-5): ")

                    if logged_in_choice == "1":
                        # Implement change password functionality
                        pass
                    elif logged_in_choice == "2":
                        password = password_generator()
                        password_strength = check_password_strength(password)
                        print(password_strength)
                        if password_strength == "Strong Password":
                            save_password(password)
                        else:
                            print("Password not saved due to weak strength.")
                    elif logged_in_choice == "3":
                        view_saved_passwords()
                    elif logged_in_choice == "4":
                        delete_password()
                    elif logged_in_choice == "5":
                        break
                    else:
                        print("Invalid choice. Please try again.")
        elif choice == "3":
            password = password_generator()
            password_strength = check_password_strength(password)
            print(password_strength)
            if password_strength == "Strong Password":
                save_password(password)
            else:
                print("Password not saved due to weak strength.")
        elif choice == "4":
            view_saved_passwords()
        elif choice == "5":
            delete_password()
        elif choice == "6":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
def change_password():
    """
    Change the password for a logged-in user.
    Prompt the user to enter the new password.
    Hash the new password and update it in the user database file.
    """
    username = input("Enter your username: ")
    new_password = input("Enter your new password: ")

    # Hash the new password
    hashed_password = hash_password(new_password)

    # Update the password in the user database file
    with open(USER_DB_FILE, "r") as user_db:
        lines = user_db.readlines()

    with open(USER_DB_FILE, "w") as user_db:
        for line in lines:
            if line.startswith(username):
                user_db.write(f"{username}:{hashed_password}\n")
            else:
                user_db.write(line)

    print("Password changed successfully!")


def reset_password():
    """
    Reset the password for a user who has forgotten it.
    Prompt the user to enter their username and a new password.
    Hash the new password and update it in the user database file.
    """
    username = input("Enter your username: ")
    new_password = input("Enter your new password: ")

    # Hash the new password
    hashed_password = hash_password(new_password)

    # Update the password in the user database file
    with open(USER_DB_FILE, "r") as user_db:
        lines = user_db.readlines()

    with open(USER_DB_FILE, "w") as user_db:
        for line in lines:
            if line.startswith(username):
                user_db.write(f"{username}:{hashed_password}\n")
            else:
                user_db.write(line)

    print("Password reset successful!")


def main():
    """
    Main program loop.
    Displays a menu with options for registration, login, password generation, viewing saved passwords, and deleting passwords.
    Based on the user's choice, calls the corresponding functions.
    """
    while True:
        print("\nPassword Generator Menu:")
        print("1. Register")
        print("2. Login")
        print("3. Generate Password")
        print("4. View Saved Passwords")
        print("5. Delete Password")
        print("6. Change Password")
        print("7. Reset Password")
        print("8. Exit")

        choice = input("Enter your choice (1-8): ")

        if choice == "1":
            register_user()
        elif choice == "2":
            if login_user():
                while True:
                    print("\nLogged in Menu:")
                    print("1. Generate Password")
                    print("2. View Saved Passwords")
                    print("3. Delete Password")
                    print("4. Change Password")
                    print("5. Logout")

                    logged_in_choice = input("Enter your choice (1-5): ")

                    if logged_in_choice == "1":
                        password = password_generator()
                        password_strength = check_password_strength(password)
                        print(password_strength)
                        if password_strength == "Strong Password":
                            save_password(password)
                        else:
                            print("Password not saved due to weak strength.")
                    elif logged_in_choice == "2":
                        view_saved_passwords()
                    elif logged_in_choice == "3":
                        delete_password()
                    elif logged_in_choice == "4":
                        change_password()
                    elif logged_in_choice == "5":
                        break
                    else:
                        print("Invalid choice. Please try again.")
        elif choice == "3":
            password = password_generator()
            password_strength = check_password_strength(password)
            print(password_strength)
            if password_strength == "Strong Password":
                save_password(password)
            else:
                print("Password not saved due to weak strength")
        elif choice == "4":
            view_saved_passwords()
        elif choice == "5":
            delete_password()
        elif choice == "6":
            change_password()
        elif choice == "7":
            reset_password()
        elif choice == "8":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()


