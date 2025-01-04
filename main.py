#Masai Project
#Bank Management System

import json
import random
import os
import base64
import bcrypt
from cryptography.fernet import Fernet
import maskpass
import re
from datetime import datetime
import smtplib

User_detail_file = "User_detail_file.json" # User Detail File.
USER_DETAIL_FILE_KEY = "User_detail_file_key.json"
USER_Transaction_FILE = "User_Transaction_file.json"

def load_key() -> bytes:
    """
    This function load key for program
    If file not exist then create new file and gennerate key using genrete_User_detail_key function.
    return key in bytes.
    """
    if os.path.exists(USER_DETAIL_FILE_KEY):
        with open(USER_DETAIL_FILE_KEY,"r") as key_file:
            key_data = json.load(key_file)
            return key_data["key"].encode()
    else:
        return genrete_User_detail_key()
    
def genrete_User_detail_key() -> bytes:
    """
    This function gennerate key for encryption and decryption.
    if file not exist then create file and write key in file
    and return key to load_file function. 
    """
    key = Fernet.generate_key()
    encode_key = key.decode()
    dict_key = {"key": encode_key}
    with open(USER_DETAIL_FILE_KEY,"w") as Key_file:
        json.dump(dict_key,Key_file)
    return key

encryption_key = load_key()
cipher = Fernet(encryption_key)

def Read_file_of_user_detail(File_name) -> bytes | None:
    """
    This function will Read the file.
    Return the data in encrypted form of bytes.
    """
    if os.path.exists(File_name) and os.stat(File_name).st_size == 0:
        return None
    elif os.path.exists(File_name):
        with open(File_name,"r") as file:
            try :
                encrypted_content = json.load(file)
                return encrypted_content
            except (json.JSONDecodeError):
                return None
    return None

def encrypte_data(data_to_encrypte: dict) -> bytes:
    """
    This function taka parameter as dict.
    and we encrypte data using key and return encrypted data in the form of bytes to store.
    """
    json_data = json.dumps(data_to_encrypte).encode()
    encrypted_data = cipher.encrypt(json_data)
    base64_encrypted_data = base64.b64encode(encrypted_data)
    return base64_encrypted_data

def decrypte_data(data_to_decrypte : bytes) -> dict:
    """
    This function take parameter as encrypted data(bytes).
    and this function decrypte the data and return dict.
    """
    encryption_data = base64.b64decode(data_to_decrypte)
    decrypted_data = cipher.decrypt(encryption_data).decode()
    User_dict = json.loads(decrypted_data)
    return User_dict
    
def genrete_Account_number(File_name: str) ->int:
    """
    This Function  genrete 6 digit Account Number.
    It does not take any parameter.
    """
    genreted_Account_number = random.randint(100000, 999999)
    
    if None == Check_Account_Number_Exist(genreted_Account_number,File_name):
        return genreted_Account_number
    else:
        genrete_Account_number(File_name)

def Account_password() -> bytes:
    """
    This function has no parameter
    In this function user input there password.
    We connvert user_password into hased password using bcrypt module
    and return hased password(bytes).
    """
    pattern = r"^(?=.*[A-Z])(?=.*[!@#$%^&*()_+{}|:<>?])(?=.{8,})"

    User_password = maskpass.advpass("Enter you password : ")
    while (not re.match(pattern,User_password)):
        print("Password must contain at least one uppercase letter, one special character, and be at least 8 characters long. Try again.")
        User_password = maskpass.advpass("Enter you password : ")

    byte_password = User_password.encode()
    salt =  bcrypt.gensalt()
    Hased_password = bcrypt.hashpw(byte_password,salt)

    return Hased_password

def Check_Account_Number_Exist(Check_Account_Number: int, File_name: str) -> str | None:
    """
    This Function Check Account Number Already in json file.
    It take parameter as Account number and file name,
    and return data of file.
    """
    encrypted_content = Read_file_of_user_detail(File_name)

    if None == encrypted_content:
        return None
    else:
        data_of_file = encrypted_content

    if str(Check_Account_Number) in data_of_file:
        return data_of_file[str(Check_Account_Number)]
    
    return None

def Add_data_to_json_file(add_dict: dict|list, File_name: str) -> bool :
    """
    This function Add data to the file
    add_dict: dictionary of data to be added
    Return the True of False base on data added successful or not.
    """
    data_of_file = Read_file_of_user_detail(File_name)
    if None == data_of_file:
        data_of_file = {}
    
    encrypted_data = encrypte_data(add_dict)

    if File_name == User_detail_file:
        data_of_file[str(add_dict["Account_number"])] = encrypted_data.decode()
    elif File_name == USER_Transaction_FILE:
        if str(add_dict[0])  not in data_of_file:
            data_of_file[str(add_dict[0])] = []
            data_of_file[str(add_dict[0])].append(encrypted_data.decode())
        else:
            data_of_file[str(add_dict[0])].append(encrypted_data.decode())

    with open(File_name,"w") as file:
        json.dump(data_of_file, file, indent=4)
    
    return True

def show_account_detail(Account_number : int) -> None:
    """
    This function use to show the account detail to user.
    this will take parameter as Account number of user and return none.
    """
    User_data = Check_Account_Number_Exist(Account_number,User_detail_file)

    if None == User_data:
        print("Account not exist enter valid Account number.")
    else:
        encrypted_data = User_data.encode()
        User_dict = decrypte_data(encrypted_data)
        print(f"Account number : {User_dict["Account_number"]}")
        print(f"User first name : {User_dict["First_name"]}")
        print(f"User last name : {User_dict["Last_name"]}")
        print(f"Bank balance : {User_dict["Bank_Balance"]}")

    input("Press enter continue.....")

def show_Transaction_hestory(Account_number : int) -> str:
    """
    This function show Transaction history of specific account where account number is parameter of this function
    and return Transaction history.
    """
    message = ""

    data = Read_file_of_user_detail(USER_Transaction_FILE)
    User_data = data[str(Account_number)]

    for encrypte_data in User_data:
        decrypted_data = decrypte_data(encrypte_data)
        message+=(f"Transfer time : {decrypted_data[4]}\nTransfer type : {decrypted_data[2]}\nTransfer(debit/credit) from : {decrypted_data[1]}\nTransfer amount : {decrypted_data[3]}\n\n")
    
    return message

def is_valid_email(email: str) -> bool:
    """
    This function check either mail is in format or not
    According to that return True and False
    """
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    
    if re.match(pattern, email):
        return True
    else:
        return False

def send_otp(email_address: str,message = None) -> int | None:
    """
    This function will send otp to your mail
    for confromation
    this function take emil address and return otp if send otherwise return none
    """

    sender_email = "bankmanagementsystemotp@gmail.com"  
    sender_password = "nqgp ipuw kxja ierc"     
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    if None == message:
        otp = random.randint(100000, 999999)
        
        # Email message if send otp
        subject = "Your OTP Code"
        message = f"Subject: {subject}\n\nYour OTP code is: {otp}"

        try:
            # Set up the email server and send the OTP
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email_address, message)
            server.quit()
            print("OTP sent successfully!")
            return otp
        except Exception:
            return None
    elif None != message:
        try:
            # Set up the email server and send the OTP
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email_address, message)
            server.quit()
            print("Mail sent successfully!")
        except Exception:
            return None
        

def space(Message: str) -> str: 
    """
    This function use for Main Handing(like Main manu)
    And also for Make Result more clear.        
    """
    return (f"\n\n------{Message}------\n\n")

def main():
    #Main menu run until user not choose to exit. 
    while True:
        print(space("Main Menu"))
        #multiple option in main menu.
        print("1. Login.")
        print("2. Create New Account.")
        print("3. Exit Program.")
        try: # if user enter wrong data type then error not genreted and code run without error.
            User_input_for_Option = int(input("Choose one of above option number : "))
        except (ValueError):
            print("Enter value again.")
        else: # if error is not genreted then it run.
            match User_input_for_Option:
                case 1:
                    while True:
                        print(space("Login page"))
                        User_account_number = int(input("Enter your account number : "))
                        User_data = Check_Account_Number_Exist(User_account_number,User_detail_file)
                        
                        if None != User_data:
                            User_dict = decrypte_data(User_data.encode())
                            User_password = maskpass.advpass("Enter Your password : ")
                            if bcrypt.checkpw(User_password.encode(),User_dict["password"].encode()):
                                while True:
                                    print(space("login menu"))
                                    print("Choose one of the option below.")
                                    print("1. Show detail of Account.")
                                    print("2. Change password.")
                                    print("3. Cash withdraw from ATM.")
                                    print("4. Transfer Money to another Account.")
                                    print("5. Show the transaction")
                                    print("6. Credit amount to account.")
                                    print("7. Back to Main menu.")
                                    User_option = int(input("Choose one of the option : "))
                                    match User_option:
                                        case 1:
                                            print(space("Account detail"))
                                            show_account_detail(User_account_number)
                                        case 2:
                                            print(space("Change password"))
                                            print(f"Sending mail {User_dict["User_Email_id"][:2]}***@***.com")
                                            mail_otp = send_otp(User_dict["User_Email_id"])
                                            if None != mail_otp:
                                                otp = int(input("Enter otp : "))
                                                if mail_otp == otp:
                                                    new_password = Account_password()
                                                    User_dict["password"]=new_password.decode()
                                                    Add_data_to_json_file(User_dict,User_detail_file)
                                                else:
                                                    print("incorrect otp. please try again.")
                                                    input("Press enter to continue.......")
                                            else:
                                                print("Enable to send otp check your internet connection.")
                                        case 3:
                                            print(space("Cash withdraw from ATM"))
                                            amount_to_debit = int(input("Enter amount to be debit : "))
                                            User_password = maskpass.advpass("Enter Your password : ")
                                            if bcrypt.checkpw(User_password.encode(),User_dict["password"].encode()) and User_dict["Bank_Balance"]>=amount_to_debit:
                                                User_dict["Bank_Balance"] -= amount_to_debit
                                                if Add_data_to_json_file(User_dict,User_detail_file):
                                                    Transaction = [User_account_number,"ATM","Debit",amount_to_debit,str(datetime.now())]
                                                    if Add_data_to_json_file(Transaction,USER_Transaction_FILE):
                                                        print(f"{amount_to_debit} is debited from {User_account_number}.")
                                                        print(f"Remaining bank balance is {User_dict['Bank_Balance']}")
                                            else:
                                                if User_dict["Bank_Balance"]<amount_to_debit:
                                                    print("Not enough amount available.")
                                                else:
                                                    print("try again.")
                                            input("Press enter to continue.....")
                                        case 4:
                                            print(space("Money Transfer to another Account"))
                                            Transfer_account = int(input("Enter Account number : "))
                                            amount_to_debit = int(input("Enter amount to be transfer : "))
                                            User_password = maskpass.advpass("Enter Your password : ")
                                            if bcrypt.checkpw(User_password.encode(),User_dict["password"].encode()) and User_dict["Bank_Balance"]>=amount_to_debit:
                                                another_user_data = Check_Account_Number_Exist(Transfer_account,User_detail_file)
                                                if None != another_user_data:
                                                    another_dict = decrypte_data(another_user_data.encode())
                                                    another_dict["Bank_Balanace"] += amount_to_debit
                                                    User_dict["Bank_Balanace"] -= amount_to_debit
                                                    if Add_data_to_json_file(User_dict,User_detail_file) & Add_data_to_json_file(another_dict,User_detail_file):
                                                        time = datetime.now()
                                                        Transaction_debit = [User_account_number,f"Transfer to {Transfer_account}","Debit",amount_to_debit,str(time)]
                                                        Transaction_credit = [Transfer_account,f"Transfer from {User_account_number}","credit",amount_to_debit,str(time)]
                                                        if Add_data_to_json_file(Transaction_debit,USER_Transaction_FILE) & Add_data_to_json_file(Transaction_credit,USER_Transaction_FILE):
                                                            print(f"{amount_to_debit} is debited from {User_account_number} and credit to {Transfer_account}.")
                                                            print(f"Remaining bank balance is {User_dict['Bank_Balanace']}")
                                                            input("Press enter to continue.......")
                                                else:
                                                    print(f"Account number not exist : {Transfer_account}.")
                                            else:
                                                if User_dict["Bank_Balance"]<amount_to_debit:
                                                    print("Not enough amount available.")
                                                else:
                                                    print("try again.")
                                        case 5:
                                            print(space(f"Transaction Histroy of Account number {User_account_number}"))
                                            message = show_Transaction_hestory(User_account_number)
                                            print(message)
                                            mail = input("If you want transaction history to mail then press\"y\" : ")
                                            if mail == "y" | mail == "Y":
                                                send_otp(User_dict["User_Email_id"],f"{space("Transaction history")}{message}")
                                            input("Press enter to coniune.......")
                                        case 6:
                                            print(space("Cash withdraw from ATM"))
                                            amount_to_credit = int(input("Enter amount to be credit : "))
                                            User_password = maskpass.advpass("Enter Your password : ")
                                            if bcrypt.checkpw(User_password.encode(),User_dict["password"].encode()):
                                                User_dict["Bank_Balance"] -= amount_to_credit
                                                if Add_data_to_json_file(User_dict,User_detail_file):
                                                    Transaction = [User_account_number,"Bank","Credit",amount_to_credit,str(datetime.now())]
                                                    if Add_data_to_json_file(Transaction,USER_Transaction_FILE):
                                                        print(f"{amount_to_credit} is credited to {User_account_number}.")
                                                        print(f"remanig bank balance is {User_dict['Bank_Balanace']}")
                                            input("Press enter to continue.....")
                                        case 7:
                                            break
                                break
                            else:
                                print(space("Try to login Again.(Wrong password)"))
                        else:
                            print(space("Try to login Again.(Account not exixted)"))
                            break
                case 2:
                    print(space("Enter Your detail to create new account : "))
                    User_account_number = genrete_Account_number(User_detail_file)
                    User_first_name = input("Enter your first name : ")
                    User_last_name = input("Enter your last name : ")
                    
                    User_email_id = input("Enter your email id : ")
                    if is_valid_email(User_email_id):
                        otp = send_otp(User_email_id)
                        User_otp = int(input("Enter otp : "))
                        while True:
                            if User_otp == otp:
                                Hased_Account_password = Account_password()
                                User_Bank_Balance = int(input("Enter amount to deposit in Account : "))
                                User_dict = {"Account_number": User_account_number, "First_name": User_first_name, "Last_name": User_last_name, "password": Hased_Account_password.decode(), "Bank_Balance": User_Bank_Balance, "User_Email_id": User_email_id}
                                if Add_data_to_json_file(User_dict,User_detail_file):
                                    print(space("New account created."))    
                                    show_account_detail(User_account_number)
                                    send_otp(User_email_id,f"Subject: Account Detail\n\n{space("Account detail")}Account Number : {User_account_number}\nUser First name : {User_first_name}\nUser last name : {User_last_name}\nBank balanace : {User_Bank_Balance}")
                                    break
                            elif otp == None:
                                print("not able to send otp, try again.....")
                                break
                            elif User_otp != otp:
                                print("Otp is incorrect, try agian .....")
                                break
                    
                case 3:
                    print(space("You exited from Bank Management System."))
                    break

if __name__ == '__main__':
    main()
