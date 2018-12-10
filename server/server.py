#!/usr/bin/python3

from flask import Flask, request, jsonify, render_template
from flask_recaptcha import ReCaptcha
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
recaptcha = ReCaptcha(app=app)
app.secret_key = b'aiOiq92!8hf_a=jfujshd;@IJN2@oJAP!@#'
CERTIFICATE = "/etc/ssl/certs/server_cert.crt"
KEY = "/etc/ssl/private/server_key.key"
LIST_OF_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '!', '@', '#', '$', ',', '.', ' ',
                      'A', 'B', 'C', 'D','E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
EMAIL_ADDRESS, PASSWORD = support_email()


def create_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='authenticator',
            password='d228685eeffbe3614efa0e994246dff980c5fba4b94487365877c63856527292ee90d24b1c76b92f57d4e6c165c2ed93a9283582acc3358e86ad5e2ea76f8730',
            database='blog')
        return conn

    except mysql.connector.Error as e:
        print(e)
    return None

def support_email():
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute('SELECT Email_ID, Password FROM support')
		result = cur.fetchone()
		cur.close()
		conn.close()
		return result[0], result[1]
	
	except mysql.connector.Error as e:
		return None

def send_email(target_email, subject, message):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
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

def create_new_user(user_email, password):
	if email_validator(user_email) == True:
		conn = create_connection()
		cur = conn.cursor()
			try:
				cur.execute('INSERT INTO users(Password, Email_ID) VALUES (%s, %s)', (hashlib.sha512(password.encode('UTF-8')).hexdigest(), user_email))
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


def authenticate(email, password):
	conn = create_connection()
	cur = conn.cursor()
	cur.execute("SELECT fName FROM users WHERE email = ? AND password = ?", (email, password))
	rows = cur.fetchall()
	cur.close()
	conn.close()
	if len(rows) == 1:
		return rows[0][0], True


@app.route('/', methods=['GET'])
def root():
	return render_template('login.html')
	

@app.route('/login', methods=['POST'])
def login():
	email = request.form.get('email')
	password = request.form.get('password')
	if authenticate(email, password):
		if recaptcha.verify():
			session['email'] = email
			name = retrieve_name(email)
			return render_template('home', name=name)
		else:
			message = "Invalid CAPTCHA code"
			return render_template('login.html', message=message)
	message = "Invalid username/password!"
	return render_template('login.html', message=message)


@app.route('/home', methods=['GET'])
def home():
	return render_template('') 
	
@app.route('/registration', methods=['GET'])
def registration():
	return render_template('registration.html')

@app.route('/register_user', methods=['POST'])
	email = request.form.get('reg_email')
	fName = request.form.get('reg_fname')
	lName = request.form.get('reg_lname')
	if check_duplicate_email(email):
		if check_password_validity(password):
			create_new_user(fName, lName, email, password)
			return render_template('')

@app.route('/logout',methods=['POST'])
def logout():
	session.pop('email', None)
	return redirect(url_for('login'))



