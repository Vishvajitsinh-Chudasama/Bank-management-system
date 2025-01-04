# Bank Management System

A Python-based Bank Management System designed to handle basic banking operations such as account creation, account details display, and fund transfer. The system supports secure password hashing, OTP-based authentication, and encryption for sensitive data storage. The system also sends transactional history via email and ensures high levels of data security.


- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Functions](#functions)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)


## Features

- **Account Creation**: Create a new bank account with an initial deposit.
- **Password Security**: Passwords are securely hashed using `bcrypt`.
- **OTP Authentication**: OTP-based email authentication for account verification.
- **Account Details**: View account details (Balance, Name, etc.).
- **Fund Transfer**: Transfer funds between accounts.
- **Email Notifications**: Transaction details are sent via email.
- **Data Encryption**: All sensitive data is encrypted using `Fernet`.
- **User-friendly Interface**: Command-line interface for seamless user interaction.


## Requirements

- Python 3.x
- `bcrypt` (for password hashing)
- `cryptography` (for data encryption)
- `maskpass` (for hiding password input)
- `smtplib` (for sending OTP and transaction emails)


## Installation

1. Clone the repository:
   
   
   git clone https://github.com/yourusername/Bank-Management-System.git
   
2. Navigate into the project directory:

  cd Bank-Management-System
  
3. Install the required dependencies:

  pip install -r requirements.txt

## 6. Running the Application

After completing the setup, you can run the application by following these steps:

1. **Navigate to the Project Directory**:
   In the terminal, navigate to the directory where the project is located. For example:

   
   cd path/to/Bank-Management-System


## 7. Features

The Bank Management System provides the following features:

1. **User Account Management**:
   - Create a new account with a secure password.
   - Login with an account number and password.
   - View and update account details.

2. **Bank Transactions**:
   - Perform ATM withdrawals.
   - Transfer money to another account.
   - View transaction history (debit/credit).

3. **Security**:
   - Password hashing and encryption for secure storage.
   - OTP (One-Time Password) sent via email for confirmation during sensitive actions like password changes.

4. **Email Integration**:
   - OTP generation and email delivery for user authentication and actions like password change or transaction history.

## 8. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
