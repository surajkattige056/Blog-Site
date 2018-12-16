import os
import datetime

http_code = str(302) # 302 is for redirection
timestamp = str(datetime.datetime.now())
user = 'suraj.kattige056@gmail.com'
request_type = "GET"

message = http_code + "    " + timestamp + "    " + user + "    " + request_type
os.system('sudo echo "' + message + '" >> ./logs/blog.log')


def retrieve_home_page():
	fread = open('./templates/home.html', 'r')
	output = ""
	body_flag = False
	script_flag = False
	nav_flag = False
	for line in fread:
		if line.strip().startswith("<body"):
			body_flag = True
		elif line.strip().startswith("</body"):
			body_flag = False
		if body_flag == True:
			
			output += line
#			if line.strip().startswith("<script"):
#				script_flag = True
			
#			if line.strip().endswith("</script"):
#				script_flag = False
			
#			elif line.strip().startswith("</script"):
#				script_flag = False
			
#			if line.strip().startswith("<nav"):
#				nav_flag = True
			
#			if line.strip().endswith("</nav"):
#				nav_flag = False
			
#			elif line.strip().startswith("</nav"):
#				nav_flag = False
			
#			elif script_flag == False and nav_flag == False:
#				output += line + "\n"
	print(output)
	fread.close()
	return output
	

def retrieve_no_body():
	fread = open('./templates/home.html', 'r')
	output = ""
	for line in fread:
		if line.strip().startswith("<body"):
			break
		output +=line
		
	for line in fread:
		output += "\n\n\nThis is getting printed now\n\n\n"
		output += line
		break
	
	print(output)

#retrieve_no_body()
#retrieve_home_page()
