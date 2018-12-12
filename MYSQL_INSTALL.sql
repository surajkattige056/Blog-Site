# Create the database
CREATE DATABASE IF NOT EXISTS blog;

USE blog;

# Drop the tables if they exist
DROP TABLE IF EXISTS login_log;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS support;
DROP TABLE IF EXISTS version;


# Create tables
CREATE TABLE IF NOT EXISTS users(
	Email_ID VARCHAR(50) NOT NULL PRIMARY KEY,
	Password VARCHAR(128) NOT NULL,
	FName VARCHAR(50) NOT NULL,
	LName VARCHAR(50) NOT NULL,
	User_Type VARCHAR(50) NOT NULL DEFAULT 'NORMAL',
	Forgot_Password_Generated VARCHAR(128) DEFAULT NULL,
	Forgot_Password_Flag INTEGER DEFAULT 0,
	Incorrect_Login_Count INTEGER NOT NULL DEFAULT 0,
	Last_Login_Attempt datetime DEFAULT NULL,
	Successful_Login datetime DEFAULT NULL,
	Disabled NUMERIC NOT NULL DEFAULT 0);


CREATE TABLE IF NOT EXISTS login_log(
	Email_ID VARCHAR(50) UNIQUE,
	IP_Address VARCHAR(50),
	Successful_Login datetime,
	Last_Login_Attempt datetime,
	Logged_In BOOLEAN NOT NULL DEFAULT 0,
	FOREIGN KEY (Email_ID) REFERENCES users(Email_ID));

CREATE TABLE IF NOT EXISTS logs(
	IP_Address VARCHAR(50) NOT NULL,
	Code INTEGER NOT NULL,
	Message TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS support(
	Email_ID VARCHAR(50) NOT NULL PRIMARY KEY,
	Password VARCHAR(64) NOT NULL);

CREATE TABLE IF NOT EXISTS version(
	Version_ID VARCHAR(128) PRIMARY KEY);


# Insert a value for your user
INSERT INTO users VALUES ('blog.email056@gmail.com', 'd6500b4142c4ac0ee4534dc20993aac787cd3e072c7fca4100478e50d8dfa1ab6b513c3aff3fb4d46e93179eebf3eef4e7c726540288ecd71ac1990b8a6c6987', 'blog', 'email', 'ADMIN', NULL, 0, 0, 0);

INSERT INTO login_log VALUES ('blog.email056@gmail.com', NULL, NULL, NULL, 0);

INSERT INTO support VALUES ('blog.info056@gmail.com', 'f9961c3abc7a217da2b5372e0c9b7f7fc04ddf6d4ceb4cf378a17af26b1b8dac');



# Create authenticator role
USE mysql;

CREATE USER IF NOT EXISTS 'authenticator'@'localhost' IDENTIFIED BY '!@#d228685eeffbe3614efa0e994246dff980c5fba4b94487365877c63856527292ee90d24b1c76b92f57d4e6c165c2ed93a9283582acc3358e86ad5e2ea76f8730ABC';

# Grant privileges to authenticator
GRANT ALL PRIVILEGES ON blog.* TO 'authenticator'@'localhost';

















































































































































































































	

