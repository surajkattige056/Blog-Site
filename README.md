# Blog-Site

Description
-----------
This is a secure blog website that is secure against OWASP top 10 Vulnerabilities. The following security features have been employed in the architecture

1) SSL Connection using self-signed digital certificates
2) Session management using flask-session
3) Session based CSRF Token generation
4) SHA512 Password Hashing
5) Input Validation using Javascript (Client side) and server side input validation using python
6) Generic Error page to handle bad and invalid requests to protect against fuzzing
7) Input sanitization to protect against XSS and SQL injection attacks

Requirements:
-------------
python = 3.5 or above
python3-pip
mysql-server
python3-dns
flask
flask-recaptcha
validate_email
Flask-Session
mysql-connector
PyJWT
requests

How to use it?
--------------
1) Run the install_requirements script on the server using the command below<br>
<i><b>Command:</b> sudo ./install_requirements</i><br>
or<br>
<i><b>Command:</b> sudo bash install_requirements</i><br>

2) Navigate to the server folder<br>
<i><b>Command:</b> cd server</i><br>

3) Start the wsgi server<br>
<i><b>Command:</b> sudo python3 wsgi.py</i><br>

4) Now the server is running on port 5000. On the client side, open the webpage by typing the ip address and port number<br>
<i><b>Syntax</b>: https://server_ip:5000/</i>

5) Since this website uses self-signed digital certificates, the CA certificate should be added to the client browser. So initially it will give you an exception. Click on advanced button and allow the exception to access the webpage.

6) You are good to go! As this website is used for educational purposes and learn about security concepts, check every code and try to break the website.
