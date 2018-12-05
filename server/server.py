#!/usr/bin/python3

from flask import Flask, request, jsonify
import json
import mysql.connector
import random
import hashlib
import jwt
import datetime
import smtplib
import sys
import re
import requests
import subprocess
import getpass

app = Flask(__name__)

CA_CERTIFICATE = '/etc/ssl/certs/CA_cert.pem'
CERTIFICATE = "/etc/ssl/certs/server_cert.crt"
KEY = "/etc/ssl/private/server_key.pem"
LIST_OF_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '!', '@', '#', '$', ',', '.', ' ',
                      'A', 'B', 'C', 'D','E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
EMAIL_ADDRESS = 'blog.email056@gmail.com'
PASSWORD = '101@Varsha'



def create_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='authenticator',
            password='101@Varsha',
            database='test')
        return conn

    except mysql.connector.Error as e:
        print(e)
    return None

def send_email(target_email, subject, message):
    try:
        server = smtplib.SMTP('email-smtp.us-west-2.amazonaws.com', 587)
        server.ehlo()
        server.starttls()
        server.login(EMAIL_ADDRESS, PASSWORD)
        msg = 'Subject: {}\n\n{}' .format(subject, message)
        server.sendmail(EMAIL_ADDRESS, target_email, msg)
        server.quit()
    except:
        return 'Server Error', 500

def random_password_generator(user_email):
    password = 'aA@1'
    for i in range(12):
        password += random.choice(LIST_OF_CHARACTERS)

    return password, hashlib.sha512(password.encode('UTF-8')).hexdigest()

def check_duplicate_email(email_id):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE Email_ID = %s", (email_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if len(rows)>0:
        return True
    return False

def check_duplicate_username(username):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE Username = %s", (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if len(rows)>0:
        return True
    return False

def create_new_user(user_id, username, user_email):
    if email_validator(user_email) == True:
        value_duplicate_username = check_duplicate_username(username)
        value_duplicate_email = check_duplicate_email(user_email)
        if (value_duplicate_username == False) and (value_duplicate_email == False):
            original_password, password = random_password_generator(user_email)
            conn = create_connection()
            cur = conn.cursor()
            try:
                cur.execute('INSERT INTO users(User_ID, Username, Password, Email_ID, Department_ID, User_Type) VALUES (%s, %s, %s, %s, %s, %s)', (user_id, username, password, user_email))
                conn.commit() #Very important step. If not used, the changes won't reflect in the config.DATABASE
            except mysql.connector.errors.ProgrammingError:
                cur.close()
                conn.close()
                return "Database unavailable. Please try again", 503
            cur.close()
            conn.close()
            subject = 'IoT HomeLab Login information'
            message = 'Hello there!\n\nCongratulations! Your account has been created on the IoT Homelab app.Please use the following are the details for it:\nUsername:' + username +'\npassword:' + original_password
            message += "\n\nPlease change your password upon login. Have a nice day!\n\nThanks and Regards,\nIoT HomeLab"
            send_email(user_email, subject, message)
            return 'Insert Operation Successful', 201

        if(value_duplicate_username == True):
            return 'Duplicate Username', 409

        if(value_duplicate_email == True):
            return 'Duplicate User email', 409

    else:
        return 'Invalid Email Address', 400

    return 'Invalid Request', 403

def secret_key_generator():
    key_length = random.randint(16, 100)
    rand_phrase = ''
    for i in range(key_length):
        rand_phrase += random.choice(LIST_OF_CHARACTERS)
    secret_key = hashlib.sha512(rand_phrase.encode('UTF-8')).hexdigest()
    return secret_key

def check_last_login(username):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT TIME_TO_SEC(NOW()) - TIME_TO_SEC(log.Last_Login_Attempt) FROM login_log log INNER JOIN users usr ON log.User_ID = usr.User_ID WHERE usr.Username = %s", ((username,)))
    rows = cur.fetchall()
    if int(rows[0][0]) > 300:
        try:
            cur.execute("UPDATE users SET Incorrect_Count = 0 WHERE Username = %s", (username,))
            conn.commit()
        except mysql.connector.errors.ProgrammingError:
            cur.close()
            conn.close()
            return 503
        return True
    cur.close()
    conn.close()
    return False

def update_disability(username):
    conn = create_connection()
    cur = conn.cursor()
    while True:
        try:
            cur.execute("UPDATE users SET Disabled = 0, Incorrect_Count = 0 WHERE Username = %s", (username,))
            conn.commit()
            break
        except mysql.connector.errors.ProgrammingError:
            pass
    cur.close()
    conn.close()

def check_disability(username):
    flag = False
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT Disabled FROM users WHERE Username = %s", (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if int(rows[0][0]) == 1:
        flag_last_login = check_last_login(username)
        if flag_last_login == True:
            update_disability(username)
        elif flag_last_login == 503:
            flag = 503
    else:
        flag = True
    return flag

def check_username_present(username):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT User_Type, User_ID FROM users WHERE Username =%s", (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if len(rows) > 0:
        return rows, True
    return rows, False

def authenticate_user(username, password):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE Username = %s AND Password = %s", (username, password))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if len(rows) > 0:
        return True
    return False

def user_authenticator(username, user_id):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT Disabled FROM users WHERE Username = %s AND User_ID = %s", (username, user_id))
    rows = cur.fetchall()
    conn.close()
    return rows

def jwt_generator(username, user_id):
    secret_key = app.config['SECRET_KEY']
    access_token = jwt.encode({'username': username, 'user_id': user_id,'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, secret_key)
    return access_token


def jwt_authenticator(access_token):
    flag = False
    try:
        data = jwt.decode(access_token.encode('UTF-8'), app.config['SECRET_KEY'])
    except jwt.exceptions.InvalidSignatureError:
        return False, 401
    except jwt.exceptions.ExpiredSignatureError:
        return False, 401
    result = user_authenticator(data['username'], data['user_id'])
    if (len(result) == 1) and (result[0][0] == 0):
        flag = True
    else:
        flag = False
    return flag, data['user_id']

def update_logout(username, db_username, db_password):
    conn = create_connection()
    cur = conn.cursor()
    while True:
        try:
            cur.execute('UPDATE login_log SET Logged_In = 0 WHERE User_ID = (SELECT User_ID FROM users WHERE Username = %s)', (username,))
            conn.commit()
            break
        except mysql.connector.errors.ProgrammingError:
            pass
    cur.close()
    conn.close()

def get_username_password(user_id):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute('SELECT Username, Password FROM users WHERE User_ID=%s', (user_id,))
    result = cur.fetchone()
    cur.close()
    conn.close()
    username = result[0]
    password = result[1]
    return username, password

def check_existing_session(user_id):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute('SELECT Logged_In FROM login_log WHERE User_ID = %s', (user_id,))
    logged_in = int(cur.fetchall()[0][0])
    cur.close()
    conn.close()
    if logged_in == 0:
        return False
    return True

def password_validator(password):
    if((len(password) < 8) or (len(password) > 50)):
        return False
    else:
        if(re.search('.*[A-Z].*', password) and re.search('.*[a-z].*', password) and re.search('.*[0-9].*', password) and re.search('.*[!@#$%^&*,./; ].*', password)):
            return True
        else:
            return False

def email_validator(email):
    if(email.count('@') == 1) and (email.endswith('.edu') or email.endswith('.com') or email.endswith('.org') or email.endswith('.net')):
        return True
    else:
        return False

def update_password(username, new_password):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT Password FROM users WHERE Username = %s", (username,))
    old_password = cur.fetchone()[0]
    try:
        cur.execute("UPDATE users SET Password = %s, First_Time_Login = 0 WHERE Username = %s", (hashlib.sha512(new_password.encode('UTF-8')).hexdigest(), username))
        conn.commit()
    except mysql.connector.errors.ProgrammingError:
        cur.close()
        conn.close()
        return 503
    cur.close()
    conn.close()
    return 201

def raise_forgot_password_flag(email_id):
    password = 'aA@1'
    for i in range(12):
        password += random.choice(LIST_OF_CHARACTERS)
    conn = create_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET Forgot_Password_Generated = %s, Forgot_Password_Flag = 1 WHERE Email_ID = %s",(hashlib.sha512(password.encode('UTF-8')).hexdigest(), email_id))
        conn.commit()
    except mysql.connector.errors.ProgrammingError:
        cur.close()
        conn.close()
        return "Database unavailable. Please try again", 503
    return password

def check_first_time_login(username):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT First_Time_Login FROM users WHERE Username = %s", (username,))
    rows = cur.fetchall()
    conn.close()
    if rows[0][0] == 1:
        return True
    return False

def create_login_log(username):
    conn = create_connection()
    cur = conn.cursor()
    while True:
        try:
            cur.execute("INSERT INTO login_log VALUES ((SELECT User_ID FROM users WHERE Username = %s), NULL, NULL, NULL, 0)", (username,))
            conn.commit()
            break
        except mysql.connector.errors.ProgrammingError:
            cur.close()
            conn.close()
    cur.close()
    conn.close()

def update_forgot_password_flag(username):
    conn = create_connection()
    cur = conn.cursor()
    while True:
        try:
            cur.execute("UPDATE users SET Forgot_Password_Generated = NULL, Forgot_Password_Flag = 0 WHERE Username = %s",(username,))
            conn.commit()
            break
        except mysql.connector.errors.ProgrammingError:
            pass
    cur.close()
    conn.close()

def update_login_attempt(username, client_ip):
    conn = create_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE login_log SET IP_Address = %s, Last_Login_Attempt = NOW() WHERE User_ID = (SELECT User_ID FROM users WHERE Username = %s)", (client_ip, username))
        conn.commit()
    except mysql.connector.errors.ProgrammingError:
        cur.close()
        conn.close()
        return "Database unavailable. Please try again", 503

def update_correct_log(username, client_ip):
    conn = create_connection()
    cur = conn.cursor()
    while True:
        try:
            cur.execute("UPDATE login_log SET IP_Address = %s, Successful_Login = NOW(), Last_Login_Attempt = NOW(), Logged_In = 1 WHERE User_ID = (SELECT User_ID FROM users WHERE Username = %s)", (client_ip, username))
            conn.commit()
            break
        except mysql.connector.errors.ProgrammingError:
            pass
    cur.close()
    conn.close()


def disable_user(username):
    conn = create_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET Disabled = 1 WHERE Username = %s", (username,))
        conn.commit()
    except mysql.connector.errors.ProgrammingError:
        cur.close()
        conn.close()
        return "Database unavailable. Please try again", 503
    cur.close()
    conn.close()

def update_incorrect_count(username):
    conn = create_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET Incorrect_Count = Incorrect_Count + 1 WHERE Username = %s", (username,))
        conn.commit()
    except mysql.connector.errors.ProgrammingError:
        cur.close()
        conn.close()
        return "Database unavailable. Please try again", 503

    cur.execute("SELECT Incorrect_Count FROM users WHERE Username = %s", (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if int(rows[0][0] > 2):
        disable_user(username)

def forgot_password_authenticator(username, forgot_password_generated):
    conn = create_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE Username = %s AND Forgot_Password_Generated = %s AND Forgot_Password_Flag = 1", (username, forgot_password_generated))
    rows = cur.fetchall()
    conn.close()
    if len(rows) > 0:
        return True
    return False

def check_version(version):
    conn = create_connection()
    cur = conn.cursor()
    while True:
        try:
            cur.execute("SELECT Version_ID FROM version");
            original_version = cur.fetchone()[0]
            cur.close()
            conn.close()
            if version == original_version:
                return True
            return False
        except mysql.connector.errors.ProgrammingError:
            pass

@app.route('/end_session',methods=['POST'])
def end_session():
    data_received = request.get_json()
    version = data_received['version']
    if check_version(version) == False:
        return jsonify({'message': 'Version not up to date. Either the app has been tampered with, or a previous version is being used. Please update the version by typing "sudo iothomelab --update"'}), 400
    value, user_type, user_id = jwt_authenticator(data_received['access_token'])
    if len(data_received['username']) > 0 and len(data_received['username']) <= 50:
        db_username, db_password = get_username_password(user_id)
        update_logout(data_received['username'], db_username, db_password)
    if value == True:
        #update_logout(data_received['username'], user_type)
        return jsonify({'message': 'Logged out'}), 200
    else:
        return jsonify({'message': 'Identity Verification unsuccessful. Loggin out'}), 401


