#!/usr/bin/python3

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, g
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

# These are the initial configurations
app = Flask(__name__)
recaptcha = ReCaptcha(app=app)
app.secret_key = os.urandom(128) #This generates a random alphanumeric characters of length 128. This is used as a secret key for the session
app.config['SALT'] = '8391JSDKjskajjfgajsO@91@!*>/' #This is the salt that is used to combine with the password adding another layer of security in the application

# This is a list of characters that will be used to generate a random password in generate_new_password function
LIST_OF_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                      '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '@', '.', '_', '!', '(', ')', '-', '+', '*', '^',
                      'A', 'B', 'C', 'D','E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']


# This is a function to create a connection with MYSQL.
# Note: MYSQL Server should be running else this will fail
def create_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='authenticator',
            password='!@#Thisistheauthenticator123',
            database='blog')
        return conn
	
# MYSQL COnnection Error will be handled here
    except mysql.connector.Error as e:
        print(e)
    return None

# Support is an email where all the feedback from the users will be sent.
# This function connects to the database and retrieves the email and password of the support team.
# @return This returns the email and password pf support
def support_email():
	try:
		conn = create_connection() # Create a connection with the database
		cur = conn.cursor() #Create a cursor. Each connection can have multiple cursors. Cursors will be used to fetch results from database
		cur.execute('SELECT Email_ID, Password FROM support') #Execute query in MySQL
		result = cur.fetchone() # Fetch one row from the query executed
		cur.close() #Close the cursor connection
		conn.close() #Close connection with database
		return result[0], result[1] #Return email and password of support

# If connection cannot be made, the error will be handled here	
	except mysql.connector.Error as e:
		return None

#The support's email and password are stored in variables EMAIL_ADDRESS and PASSWORD
EMAIL_ADDRESS, PASSWORD = support_email()

# This function is used to send an email to the target.
# @param email address of the target, subject of the email, message is the body of the email
def send_email(target_email, subject, message):
    try:
        server = smtplib.SMTP('smtp.gmail.com:587') #This is the SMTP server of gmail operating on port 587
        server.ehlo()
        server.starttls() #Starts a secure SSL/TLS connection
        server.login(EMAIL_ADDRESS, PASSWORD) #Login to the server using the email address and password of the support
        msg = 'Subject: {}\n\n{}' .format(subject, message) #Write the subject and body.
        server.sendmail(EMAIL_ADDRESS, target_email, msg) #Send the email to the target
        server.quit() #Close the connection with the gmail SMTP server.
    except:
        return 'Server Error', 500 #If the server cannot be connected, return a server error with error code 500


# Check if the email already exists in the database
# @param email id
# @return return True if the email exists in the database, else return False
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

# If the connection cannot be made with MySQL, Catch the error here and return error message 503	
	except mysql.connector.errors.ProgrammingError:
		return 503

# Create new user in the database
# Password in this will be recieved in clear text To store in the database the below login will be applied
# database_password = sha512(sha512(password) + salt)

# @param user email address, password, first name, last name
# @return return code 201 if user has been inserted into database
def create_new_user(user_email, password, fName, lName):
	try:
		password = hashlib.sha512(((hashlib.sha512(password.encode('UTF-8')).hexdigest()) + app.config['SALT']).encode('UTF-8')).hexdigest() # database_password = sha512(sha512(password) + salt)
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

# Update the log of the user. This function will be called when the user logs into the database successfully.
# Two fields will be updated in the database with the current times datetime stamp - Last_Login_Attempt and Successful_Login fields

# @param email address of the user
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


# This function will be called if the the user has logged in with the forgot password.
# If the password matches with the forgot_password_generated field in the database, then it returns the first name and value true indicating that it is the user's forgot password

# @param Email address of the user and the hashed password
# @return (first name and True) or (None and False)
def check_if_forgotten_password(email, password):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT FName FROM users WHERE Email_ID=%s AND Forgot_Password_Flag = 1 AND Forgot_Password_Generated=%s", (email, password))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows) == 1:
			return rows[0][0], True #Returns first name and true if it is the forgot password
		return None, False
		
	
	except mysql.connector.errors.ProgrammingError:
		return 503

# This function will be used to authenticate a users email and password
# The password when recieved will be hashed in HTML using SHA512 algorithm
# The email address and password will be checked in the database, if it exists, return firstname, True or False if the username and password is authentic or not

# @param email address and password of the user
# @return (First name, boolean True if the email and password is authentic, and code) or (First name, True and code 201 if it is a forgot password) or (None, False and 400 bad request error code)
def authenticate(email, password):
	try:
		conn = create_connection()
		cur = conn.cursor()
		password = hashlib.sha512((password + app.config['SALT']).encode('UTF-8')).hexdigest() # database password = sha512(hashed_password + salt)
		cur.execute("SELECT FName FROM users WHERE Email_ID = %s AND Password=%s", (email, password))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows) == 1: # If the email and password are authentic
			flag = update_correct_log(email) # Update the timestamps if the user is authenticated 
			if flag == 503: # An error occurred while connecting to the database
				return None, 503, None 
			return rows[0][0], True, 200
		else: #Check if it is a forgotten password
			name, flag = check_if_forgotten_password(email, password) 
			if flag == True: # Yes, it is a forgotten password
				return name, True, 201 
			if flag == 503: # An error occurred while connecting to the database
				return None, 503, None
		return None, False, 400 # No it was not forgot password, so the email and password are both not authentic
	
	except mysql.connector.errors.ProgrammingError:
		return None, 503


# User disabled function checks if the email address has been disabled by the system
# This is a security feature implemented in the website where the user can have atmost 3 consecutive incorrect login attempts
# If 3 consecutive incorrect login attempts are encountered, then the user is disabled for 5 minutes

# @param email address of the user
# @return True if disabled, else return False
def user_disabled(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT Disabled FROM users WHERE Email_ID = %s", (email,))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows) == 1: # Checks if the user exist
			if int(rows[0][0])  == 1: # Check if the user is disabled (1) or not (0)
				flag_last_login = check_last_login(email) # Check if 5 minutes has passed since the user has been disabled. If it has, then the user is not disabled anymore
				if flag_last_login == False: # User account has been disabled for less than 5 minutes
					return False
				if flag_last_login == 503: # Database error
					return 503
				return True # User is not disabled
			return False
		else: #If the user does not exist, send error 400 (Bad request)
			return 400
	
	except mysql.connector.errors.ProgrammingError:
		return 503
		

# Check if 5 minutes has passed since there has been an incorrect login attempt
# If it has passed, set the disabled and incorrect_count fields to 0 and return False, else True.

# @param Email address of the user
# @return False if the user is not disabled, True is the user is disabled.
def check_last_login(email):
	try:
		conn = create_connection()
		cur  = conn.cursor()
		cur.execute("SELECT TIME_TO_SEC(NOW()) - TIME_TO_SEC(Last_Login_Attempt) FROM users WHERE Email_ID = %s", (email,)) #Calculate the difference between the last incorrect login attempt and the current time
		rows = cur.fetchone()
		if int(rows[0]) > 300: # If 5 minutes have passed (5 * 60 seconds = 300)
			cur.execute("UPDATE users SET Incorrect_Login_Count = 0, Disabled = 0 WHERE Email_ID=%s", (email,)) # THe user is not disabled anymore. Set the incorrect login count and disabled flag to 0
			conn.commit()
			cur.close()
			conn.close()
			return False
		cur.close()
		conn.close()
		return True
		
	except mysql.connector.errors.ProgrammingError:
		return 503

# This function is used to update the incorrect_login_count, last_login_attempt and disabled fields for incorrect login attempt
# When there is an incorrect login attempt, increment the consecutive incorrect login field by 1 and the last_login_attempt field to the current timestamp
# If there have already been 3 consecutive login attempts, then disable the user by changing the disabled flag to 1

# @param email address of the user
def update_incorrect_login(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT Incorrect_Login_Count FROM users WHERE Email_ID=%s", (email,)) # Retrieve the incorrect login count of the user
		rows = cur.fetchone()
		if int(rows[0]) == 3: # Check if there are 3 consecutive incorrect login attempts
			cur.execute("UPDATE users SET Incorrect_Login_Count = 0, Disabled = 1, Last_Login_Attempt = NOW() WHERE Email_ID=%s", (email,)) # Update the disabled field to 1, the incorrect_login_count to 0 and last_login attempt to the current timestamp
		else: # There have been less than 3 consecutive login attempts
			cur.execute("UPDATE users SET Incorrect_Login_Count = Incorrect_Login_Count + 1, Last_Login_Attempt = NOW() WHERE Email_ID=%s", (email,)) # Increase the incorrect login count to 1
		conn.commit() # save the changes made to the database
		cur.close()
		conn.close()
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 503
	

# This is used to generate a random password. This functionality will be used to generate the a random password for the user during the forgot password module
# @return The random password generated
def generate_new_password():
	password = 'aA@1' # Hard code the first 4 characters to conform to the password policy
	for i in range(12): # Generate the next 12 characters. The random password will be 16 characters long
		password += random.choice(LIST_OF_CHARACTERS)
	return password

# This password will be used to set the random password generated during the forgot password module
# @param Email address of the user and the password
def set_forgot_password(email, password):
	try:
		conn = create_connection()
		cur = conn.cursor()
		rows = cur.fetchone()
		cur.execute("UPDATE users SET Incorrect_Login_Count=0, Forgot_Password_Generated=%s, Forgot_Password_Flag = 1 WHERE Email_ID=%s", (password, email)) #Set the forgot_password_flag to 1 stating the user has forgotten the password and generated a new temporary password
		conn.commit()
		cur.close()
		conn.close()
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 503

# This is used to validate/sanitize the fields we recieve from the user
# @param: s = value, var_name = name of the input field
# @return (True, 'Valid') If the field value is value, else (False, 'Invalid')
def validate_input(s, var_name):
	if len(s) <= 0: # Checks if the field is empty or not
		return False, "Please enter " + var_name
	
	if len(s) > 50 or (not re.match('^[a-zA-Z0-9#&]*$', s)): # Checks if the field is greater than 50 characters or does not conform to the rule
		return False, 'Invalid ' + var_name

	return True, 'Valid'

# This function validates/sanitizes the feedback field given by the user
# @param COntains the feedback from the user
# @return True after sanitizing the input, False if the feedback is blank
def validate_feedback(feedback):
	if len(feedback) <= 0: # Check if the feedback field is blank
		return False, "Please enter the feedback and then submit"
	
	feedback = feedback.replace('<', "&lt")
	feedback = feedback.replace('>', "&gt");
	feedback = feedback.replace('"', "&quot");
	feedback = feedback.replace("'", "&#x27");
	feedback = feedback.replace("/", "&#x2F");
	return True, feedback

# This function is used to validate the password to check if it conforms to the password rules.
# This function will be used during the user registration to validate the passwords given there
# @param Password given by the user during registration
def validate_password(password):
	if(len(password) < 8):
		return False
	if(re.search('.*[A-Z].*', password) and re.search('.*[a-z].*', password) and re.search('.*[0-9].*', password) and re.search('.*[@._!()-+*^].*', password)):
		return True
	return False

def retrieve_name_user_type(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT FName, User_Type FROM users WHERE Email_ID = %s", (email,))
		rows = cur.fetchone()
		cur.close()
		conn.close()
		if len(rows)>0:
			return rows[0], rows[1]
		return None, None
	
	except mysql.connector.errors.ProgrammingError:
		return 503

def equal_passwords(password, confirm_password):
	if password != confirm_password:
		return False
	return True

def retrieve_user_type(email):
	try:
		conn = create_connection()
		cur = conn.cursor()
		cur.execute("SELECT User_Type FROM users WHERE Email_ID=%s", (email,))
		rows = cur.fetchall()
		cur.close()
		conn.close()
		if len(rows) == 1:
			return rows[0]
		return None
	
	except mysql.connector.errors.ProgrammingError:
		return 503

def retrieve_home_page():
	fread = open('./templates/home.html', 'r')
	output = ""
	body_flag = False
	nav_flag = False
	for line in fread:
		if line.strip().startswith("<body"):
			body_flag = True
		
		elif line.strip().startswith("</body"):
			body_flag = False
		
		elif body_flag == True:	
			if line.strip().startswith("<nav"):
				nav_flag = True
			
			if line.strip().endswith("</nav"):
				nav_flag = False
			
			elif line.strip().startswith("</nav"):
				nav_flag = False
			
			elif nav_flag == False:
				output += line
		
	fread.close()
	return output

def edit_home_page(new_content):
	files = ['./templates/home.html', './templates/home-admin.html']
	for filename in files:
		fread = open(filename, 'r')
		output = ""
		for line in fread:
			output += line
			if line.strip().startswith("</nav"):
				break
		
		output += new_content
		after_body_flag = False
		for line in fread:
			if line.strip().startswith("</body"):
				output += line
				after_body_flag = True
		
			if after_body_flag == True:
				output += line
		fread.close()
		
		fwrite = open(filename, 'w')
		fwrite.write(output)
		fwrite.close()
	return True	
		

@app.route('/', methods=['GET'])
def root():
	if 'email' in session:
		return redirect(url_for('home'))
	g.user = None
	return render_template('login.html')

@app.before_request
def before_request():
	g.user = None
	if 'email' in session:
		g.user=session['email']
	
def generate_csrf_token():
	if '_csrf_token' not in session:
		session['_csrf_token'] = os.urandom(128)
	return session['_csrf_token']
	
app.jinja_env.globals['csrf_token'] = generate_csrf_token
	
@app.route('/login', methods=['POST', 'GET'])
def login():
	if request.method == 'GET':
		if 'email' in session:
			return redirect(url_for('home'))
	if 'email' in session:
		return redirect(url_for('home'))
	try:
		if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
			return redirect(url_for('logout'))

	except KeyError:
		return redirect(url_for('error'))
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
	disabled = user_disabled(email)
	if disabled == True:
		message = "User has been disabled! Please try again later"
		return render_template('login.html', message=message)
	if disabled == 503:
		return redirect(url_for('error'))
	if disabled == 400:
		return render_template('login.html', message='Invalid Email Address/Password')
	first_name, authenticity_flag, code = authenticate(email, password)
	if authenticity_flag == True and code == 200:
		if recaptcha.verify():
			session['email'] = email
			return redirect(url_for('home'))
		else:
			message = "Invalid CAPTCHA code"
			return render_template('login.html', message=message)
	elif authenticity_flag == True and code == 201:
		session['email'] = email
		return render_template('update_password.html', name=first_name)
	elif authenticity_flag == 503:
		return redirect(url_for('error'))
	message = "Invalid Email Address/Password!"
	code = update_incorrect_login(email)
	if code != None and code == 503:
		return redirect(url_for('error'))
	return render_template('login.html', message=message)


@app.route('/home', methods=['GET'])
def home():
	if 'email' in session:
		first_name, user_type = retrieve_name_user_type(session['email'])
		if first_name != None:
			if user_type.upper() == 'NORMAL':
				return render_template('/home.html', name=first_name.capitalize())
			
			elif user_type.upper() == 'ADMIN':
				return render_template('/home-admin.html', name=first_name.capitalize())
			return redirect(url_for("error"))
		else:
			return redirect(url_for('error'))
	else:
#		return render_template('login.html')
		return redirect(url_for('login'))

@app.route('/error', methods=['GET'])
def error():
	return render_template('error.html')

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
	if request.method == 'GET':
		return redirect(url_for('home'))
	
	if g.user:
		try:
			if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
				return redirect(url_for('logout'))

		except KeyError:
			return redirect(url_for('error'))
		feedback = request.form.get('feedback')
		flag, feedback = validate_feedback(feedback)
		if flag == False:
			first_name, user_type = retrieve_name_user_type(session['email'])
			if user_type.upper() == 'NORMAL':
				return render_template('home.html', name=first_name, message=result)
			
			elif user_type.upper() == 'ADMIN':
				return render_template('home-admin.html', name=first_name, message=result)
			
			else:
				return redirect(url_for('error'))
				
		subject = "Feedback from " + session['email']
		message = 'Hello,\n\You have recieved the following review from the user\n\n"' + feedback + '"\n\nThanks and Regards,\nSecurity Blog'
		send_email(EMAIL_ADDRESS, subject, message)
		return render_template('feedback_received.html')
	else:
		return render_template('login.html', message = "Invalid session")
	
@app.route('/registration', methods=['GET'])
def registration():
	if g.user:
		return redirect(url_for('home'))
	return render_template('registration.html')

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
	if request.method == 'GET' or g.user:
			return redirect(url_for('home'))
			
	try:
		if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
			return redirect(url_for('logout'))

	except KeyError:
		return redirect(url_for('error'))
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
			return redirect(url_for('root'))
		result = "Successful"
		message = "Email Address has been registered successfully. Please go to the login page and log in with your email and password. Thank you for joining us!"
		return render_template('registration_msg.html', result=result, message=message)
	
	elif check_duplicate_email(email) == True:
		message = "Email Address already exists"
		
	elif check_duplicate_email(email) == 503:
		return redirect(url_for('error'))
	return render_template('registration.html', message=message)


@app.route('/forgot_password', methods=['GET'])
def forgot_password():
	if g.user:
		return redirect(url_for('home'))
	return render_template('forgot_password.html')
	
@app.route('/send_recovery_password', methods=['POST'])
def send_recovery_password():
	if g.user:
		return redirect(url_for('home'))
	try:
		if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
			return redirect(url_for('logout'))

	except KeyError:
		return redirect(url_for('error'))
	email = request.form.get('forgot_email')
	email_is_valid = validate_email(email)
	if email_is_valid:
		if check_duplicate_email(email):
			message = "A recovery password has been sent to your email address! Please follow the steps mentioned in the mail."
			password = generate_new_password()
			hashed_password = hashlib.sha512(((hashlib.sha512(password.encode('UTF-8')).hexdigest()) + app.config['SALT']).encode('UTF-8')).hexdigest()
			flag = set_forgot_password(email, hashed_password)
			if flag == 503:
				if 'email' in session:
					session.pop('email', None)
				return render_template('error.html')
			subject = "Security Blog Forgot Password"
			email_message = "Hello there!\n\nLooks like you forgot your password. Don't you worry! Login with this password:" + password + '\n\nThanks and Regards,\nSecurity Blog'
			send_email(email, subject, email_message)
			return render_template('recovery_password_sent.html', message=message)
		elif check_duplicate_email(email) == False:
			message = "This email has not been registered. Please <a href='http://192.168.0.16:5000/registration'>register<a>"
			return render_template('recovery_password_sent.html', message=message)
		
		elif check_duplicate_email(email) == 503:
			return redirect(url_for('error'))
	message = "Invalid Email. Please try again"
	return render_template('forgot_password.html', message=message)
	
@app.route('/change_password', methods=['GET'])
def change_password():
	if g.user:
		return redirect(url_for('home'))
	return render_template('update_password.html')


@app.route('/edit-page', methods=['GET'])
def edit_page():
	if g.user:
		content = retrieve_home_page()
		return render_template('edit_page.html', content=content)
	return redirect(url_for('root'))

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
	if request.method == 'GET':
		return redirect(url_for('home'))
		
	if g.user:
		try:
			if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
				return redirect(url_for('logout'))

		except KeyError:
			return redirect(url_for('error'))
		password = request.form.get('update_password')
		confirm_password = request.form.get('update_confirm_password')
		if password != confirm_password:
			message = "The password fields do not match"
			return render_template('update_password.html', message=message)
		if validate_password(password) == False:
			message = "Invalid password. Please conform to the password policy and try again."
			return render_template('update_password.html', message=message)
		try:
			password = hashlib.sha512(((hashlib.sha512(password.encode('UTF-8')).hexdigest()) + app.config['SALT']).encode('UTF-8')).hexdigest()
			conn = create_connection()
			cur = conn.cursor()
			cur.execute("UPDATE users SET Password = %s, Forgot_Password_Generated=NULL, Forgot_Password_Flag = 0, Incorrect_Login_Count = 0 WHERE Email_ID = %s", (password, session['email']))
			conn.commit()
			cur.close()
			conn.close()
			
		except mysql.connector.errors.ProgrammingError:
			return redirect(url_for('error')) 
			
		if g.user:
			if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
				redirect(url_for('home'))
			g.user = None
			session.pop('email', None)
			session.pop('_csrf_token', None)
		return render_template('password_changed.html', message='Password Changed Successfully!')


@app.route('/edit-page-successful', methods=['POST'])
def edit_page_successful():
	if g.user:
		try:
			if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
				return redirect(url_for('logout'))

		except KeyError:
			return redirect(url_for('error'))
		result = edit_home_page(request.form.get('edit_page_content'))
		if result == True:
			return render_template('edit_page_successful.html')
		
		elif result == False:
			return redirect(url_for('edit_page_failed'))
			
		return redirect(url_for('error'))
	
	return redirect(url_for('logout'))
		

@app.route('/edit-page-failed', methods=['GET'])
def edit_page_failed():
	if g.user:
		return render_template('edit_page.html', message="Page edit was unsuccessful. Please try again")
	
	else:
		return redirect(url_for('logout'))
	
@app.route('/logout',methods=['GET', 'POST'])
def logout():
	if g.user:
		try:
			if request.form.get('_csrf_token') == None or request.form.get('_csrf_token') != str(session['_csrf_token']):
				return redirect(url_for('logout'))

		except KeyError:
			return redirect(url_for('error'))
		g.user = None
		session.pop('email', None)
		session.pop('_csrf_token', None)
		
	
	return render_template('login.html', message='User has been logged out')




