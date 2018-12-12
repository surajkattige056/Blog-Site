#!/usr/bin/python3

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_recaptcha import ReCaptcha
from validate_email import validate_email
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
import os

app = Flask(__name__)
recaptcha = ReCaptcha(app=app)
app.secret_key = os.urandom(128)
app.config['SALT'] = '8391JSDKjskajjfgajsO@91@!*>/'
CERTIFICATE = "/etc/ssl/certs/server_cert.crt"
KEY = "/etc/ssl/private/server_key.key"
LIST_OF_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '@', '.', '_', '!', '(', ')', '-', '+', '*', '^',
                      'A', 'B', 'C', 'D','E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']



def create_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='authenticator',
            password='!@#Thisistheauthenticator123',
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

EMAIL_ADDRESS, PASSWORD = support_email()

def send_email(subject, message):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.ehlo()
        server.starttls()
        server.login(EMAIL_ADDRESS, PASSWORD)
        msg = 'Subject: {}\n\n{}' .format(subject, message)
        server.sendmail(EMAIL_ADDRESS, 'blog.email056@gmail.com', msg)
        server.quit()
    except:
        return 'Server Error', 500

def random_password_generator(user_email):
    password = 'aA@1'
    for i in range(12):
        password += random.choice(LIST_OF_CHARACTERS)

    return password, hashlib.sha512(password.encode('UTF-8')).hexdigest()

def check_duplicate_email(email_id):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT * FROM users WHERE Email_ID = %s", (email_id,))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows)>0:
			return True
		return False
	
	except mysql.connector.errors.ProgrammingError:
		return 500

def create_new_user(user_email, password, fName, lName):
	try:
		password = hashlib.sha512(((hashlib.sha512(password.encode('UTF-8')).hexdigest()) + app.config['SALT']).encode('UTF-8')).hexdigest()
		conn = create_connection()
		cur = conn.cursor()
		cur.execute('INSERT INTO users(Email_ID, Password, FName, LName) VALUES (%s, %s, %s, %s)', (user_email, password, fName, lName))
		conn.commit() 
		cur.close()
		conn.close()
		return 'Insert Operation Successful', 201
		
	except mysql.connector.errors.ProgrammingError:
		cur.close()
		conn.close()
		return "Database unavailable. Please try again", 503
	
	



def secret_key_generator():
    key_length = random.randint(16, 100)
    rand_phrase = ''
    for i in range(key_length):
        rand_phrase += random.choice(LIST_OF_CHARACTERS)
    secret_key = hashlib.sha512(rand_phrase.encode('UTF-8')).hexdigest()
    return secret_key


def update_correct_log(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("UPDATE users SET Incorrect_Login_Count = 0, Last_Login_Attempt = NOW(), Successful_Login = NOW(), Forgot_Password_Generated = NULL, Forgot_Password_Flag = 0 WHERE Email_ID=%s",(email,))
		conn.commit()
		cur.close()
		conn.close()
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 503


def authenticate(email, password):
	try:
		conn = create_connection()
		cur = conn.cursor()
		password = hashlib.sha512((password + app.config['SALT']).encode('UTF-8')).hexdigest()
		cur.execute("SELECT FName FROM users WHERE Email_ID = %s AND (Password=%s OR Forgot_Password_Generated=%s)", (email, password, password))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows) == 1:
			flag = update_correct_log(email)
			if flag == 503:
				return 503, True
			return rows[0][0], True
		return None, False
	
	except mysql.connector.errors.ProgrammingError:
		return None, 503

def user_disabled(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT Disabled FROM users WHERE Email_ID = %s", (email,))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows) == 1:
			if int(rows[0][0])  == 1:
				flag_last_login = check_last_login(email)
				if flag_last_login == False:
					return False
				if flag_last_login == 503:
					return 503
				return True
			return False
		else:
			return 400
	
	except mysql.connector.errors.ProgrammingError:
		return 500
		

def check_last_login(email):
	try:
		conn = create_connection()
		cur  = conn.cursor()
		cur.execute("SELECT TIME_TO_SEC(NOW()) - TIME_TO_SEC(log.Last_Login_Attempt) FROM users WHERE Email_ID = %s", (email,))
		rows = cur.fetchone()
		if int(rows[0]) > 300:
			cur.execute("UPDATE users SET Incorrect_Count = 0, Disabled = 0 WHERE Email_ID=%s", (email,))
			conn.commit()
			cur.close()
			conn.close()
			return True
		cur.close()
		conn.close()
		return False
		
	except mysql.connector.errors.ProgrammingError:
		return 503

def update_incorrect_login(email):
	try:
		conn = create_database()
		cur = conn.cursor()
		cur.execute("SELECT Incorrect_Count FROM users WHERE Email_ID=%s", (email,))
		rows = cur.fetchone()
		if int(rows[0]) == 3:
			cur.execute("UPDATE users SET Incorrect_Login_Count = 0, Disabled = 1, Last_Login_Attempt = NOW() WHERE Email_ID=%s", (email,))
		else:
			cur.execute("UPDATE users SET Incorrect_Login_Count = Incorrect_Login_Count + 1, Last_Login_Atempt = NOW() WHERE Email_ID=%s", (email,))
		conn.commit()
		cur.close()
		conn.close()
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 500
	

def generate_new_password(email):
	password = 'aA@1'
	for i in range(12):
		password += random.choice(serverConfig.LIST_OF_CHARACTERS)
	return password


def set_forgot_password(email, password):
	try:
		conn = create_database()
		cur = conn.cursor()
		rows = cur.fetchone()
		cur.execute("UPDATE users SET Incorrect_Login_Count=0, Forgot_Password_Generated=%s, Forgot_Password_Flag = 1 WHERE Email_ID=%s", (password, email))
		conn.commit()
		cur.close()
		conn.close()
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 500

def validate_input(s, var_name):
	if len(s) <= 0:
		return False, "Please enter " + var_name
	
	if len(s) > 50 or (not re.match('^[a-zA-Z0-9]*$', s)):
		return False, 'Invalid ' + var_name

	return True, 'Valid'

def validate_feedback(feedback):
	if len(feedback) <= 0:
		return False, "Please enter the feedback and then submit"
	
	feedback = feedback.replace('<', "&lt")
	feedback = feedback.replace('>', "&gt");
	feedback = feedback.replace('"', "&quot");
	feedback = feedback.replace("'", "&#x27");
	feedback = feedback.replace("/", "&#x2F");
	return True, feedback
	
def validate_password(password):
	if(len(password) < 8):
		return False
	if(re.search('.*[A-Z].*', password) and re.search('.*[a-z].*', password) and re.search('.*[0-9].*', password) and re.search('.*[@._!()-+*^].*', password)):
		return True
	return False

def retrieve_first_name(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT FName FROM users WHERE Email_ID = %s", (email,))
		rows = cur.fetchone()
		cur.close()
		conn.close()
		if len(rows)>0:
			return rows[0]
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 500

def equal_passwords(password, confirm_password):
	if password != confirm_password:
		return False
	return True

@app.route('/', methods=['GET'])
def root():
	if 'email' in session:
		return redirect(url_for('home'))
	return render_template('login.html')
	
	
@app.route('/login', methods=['POST'])
def login():
	if 'email' in session:
		return redirect(url_for('home'))
	
	if request.form.get('CSRFToken') == None or request.form.get('CSRFToken') != 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUaGlzIGlzIGEgSldUIHRva2VuIGZvciB0aGUgbG9naW4gcGFnZSJ9.FAhosOFOx5cbLGAZ8bFE2hnD7b6e2479TD7NXS8PV-k':
		return redirect(url_for('logout'))
	email = request.form.get('email')
	if len(email) <= 0:
		message = "Please type the email address"
		return render_template('login.html', message=message)
	if len(email) > 50:
		message = "Invalid Email"
		return render_template('login.html', message = message)
	password = request.form.get('password')
	if validate_email(email) == False:
		message = "Invalid username/password!"
		return render_template('login.html', message=message)
	if user_disabled(email) == True:
		message = "User has been disabled! Please try again later"
		return render_template('login.html', message=message)
	if user_disabled(email) == 503:
		print("It is coming here")
		return render_template('error.html')
	if user_disabled(email) == 400:
		return render_template('login.html', message='Invalid Email Address/Password')
	first_name, authenticity_flag = authenticate(email, password)
	if authenticity_flag == True:
		if recaptcha.verify():
			session['email'] = email
			return redirect(url_for('home'))
		else:
			message = "Invalid CAPTCHA code"
			return render_template('login.html', message=message)
	elif authenticity_flag == 503:
		print("No, It is coming here")
		return render_template('error.html')
	message = "Invalid Email Address/Password!"
	update_incorrect_login(email)
	return render_template('login.html', message=message)


@app.route('/home', methods=['GET'])
def home():
	if 'email' in session:
		first_name = retrieve_first_name(session['email'])
		if first_name != None:
			return render_template('/home.html', name=first_name)
		else:
			return render_template('error.html')
	else:
		return redirect(url_for('/'))

@app.route('/feedback', methods=['POST'])
def recieve_feedback():
	if 'email' in session:
		if request.form.get('CSRFToken') == None or request.form.get('CSRFToken') != 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUaGlzIGlzIGEgSldUIHRva2VuIGZvciB0aGUgZmVlZGJhY2sgcGFnZSJ9.kp-nvBgrEEf0PrCdtr5ahVdu_z2y29g7zJad0FJgAAg':
			return redirect(url_for('logout'))
		feedback = request.form.get('feedback')
		flag, feedback = validate_feedback(feedback)
		if flag == False:
			return render_template('home.html', message=result) 
		subject = "Feedback from " + session['email']
		message = "Hello,\n\You have recieved the following review from the user\n'" + feedback + "'\n\nThanks and Regards,\nSecurity Blog"
		send_email(subject, message)
	else:
		return render_template('login.html', message = "Invalid session")
	
@app.route('/registration', methods=['GET'])
def registration():
	if 'email' in session:
		return redirect(url_for('home'))
	return render_template('registration.html')

@app.route('/register_user', methods=['POST'])
def register_user():
	if 'email' in session:
		return redirect(url_for('home'))
	if request.form.get('CSRFToken') == None or request.form.get('CSRFToken') != 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUaGlzIGlzIGEgSldUIHRva2VuIGZvciByZWdpc3RyYXRpb24gcGFnZSJ9.w4XBU_n6NKUa1sdh6LUmZN5wnjMYyXRhyQ-46PxKWdk':
		return redirect(url_for('logout'))
	email = request.form.get('reg_email')
	fName = request.form.get('reg_fname')
	flag, result = validate_input(fName, 'First Name')
	if flag == False:
		return render_template('registration.html', message = result)
	lName = request.form.get('reg_lname')
	flag, result = validate_input(lName, 'Last Name')
	if flag == False:
		return render_template('registration.html', message = result)
	
	if validate_email(email) == False:
		message= "Invalid Email. Please enter a valid email address"
		return render_template('registration.html', message=message)
	
	password = request.form.get('password')
	if validate_password(password) == False:
		message = "Invalid Password. Please conform to the password rules"
		return render_template('registration.html', message=message)
	
	confirm_password=request.form.get('confirm_password')
	if validate_password(confirm_password) == False:
		message = "Invalid Confirm Password. Please conform to the password rules"
		return render_template('registration.html', message=message)
		
	if equal_passwords(password, confirm_password) == False:
		message = "Both passwords are not equal. Please try again"
		return render_template('registration.html', message=message) 
		
	if check_duplicate_email(email) == False:
		result, code = create_new_user(email, password, fName, lName)
		if code == 503:
			return redirect(url_for('/'))
		result = "Successful"
		message = "Email Address has been registered successfully. Please go to the login page and log in with your email and password. Thank you for joining us!"
		return render_template('registration_msg.html', result=result, message=message)
	else:
		message = "Email Address already exists"
	return render_template('registration.html', message=message)


@app.route('/forgot_password', methods=['GET'])
def forgot_password():
	if 'email' in session:
		return redirect(url_for('home'))
	return render_template('forgot_password.html')
	
@app.route('/send_recovery_password', methods=['GET'])
def send_recovery_password():
	if 'email' in session:
		return redirect(url_for('home'))
	if request.form.get('CSRFToken') == None or request.form.get('CSRFToken') != 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUaGlzIGlzIGEgSldUIHRva2VuIGZvciBmb3Jnb3QgcGFzc3dvcmQgcGFnZSJ9.knfJw7Z0W9LI750IERY94jHgOYhsiE1kBR2rIWn8RYE':
		return redirect(url_for('logout'))
	email = request.form.get('forgot_email')
	email_is_valid = validate_email(email, verify=True)
	if email_is_valid:
		if check_duplicate_email(email):
			message = "A recovery password has been sent to your email address! Please follow the steps mentioned in the mail."
			password = generate_new_password(email)
			hashed_password = hashlib.sha512(((hashlib.sha512(password.encode('UTF-8')).hexdigest()) + app.config['SALT']).encode('UTF-8')).hexdigest()
			flag = set_forgot_password(email, hashed_password)
			if flag == 500:
				if 'email' in session:
					session.pop('email', None)
				return render_template('error.html')
			subject = "Security Blog Forgot Password"
			message = "Hello there!\n\nLooks like you forgot your password. Don't you worry! Login with this password:" + password
			send_email(email, subject, message)
			return render_template('recovery_password_sent.html', message=message)
		else:
			message = "This email has not been registered. Please <a href='http://192.168.0.16:5000/registration'>register<a>"
			return render_template('recovery_password_sent.html', message=message)
	message = "Invalid Email. Please try again"
	return render_template('forgot_password.html', message=message)
	
@app.route('/change_password', methods=['GET'])
def change_password():
	if 'email' in session:
		return redirect(url_for('home'))
	return render_template('change_password.html')

@app.route('/update_password', methods=['POST'])
def update_password():
	if 'email' in session:
		if request.form.get('CSRFToken') == None or request.form.get('CSRFToken') != '':
			return redirect(url_for('logout'))
		password = request.form.get('update_password')
		confirm_password = request.form.get('update_password')
		if password != confirm_password:
			message = "The password fields do not match"
			return render_template('change_password.html', message=message)
		if validate_password(password) == False:
			message = "Invalid password. Please conform to the password policy and try again."
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("UPDATE users SET Password = %s, Forgot_Password_Generated=NULL, Forgot_Password_Flag = 0, Incorrect_Login_Count = 0 WHERE Email_ID = %s", (password, session['email']))
		conn.commit()
		cur.close()
		conn.close()
		return redirect(url_for('logout'))
	
	
@app.route('/logout',methods=['POST'])
def logout():
	if 'email' in session:
		session.pop('email', None)
	return render_template('login.html', message='User has been logged out')




