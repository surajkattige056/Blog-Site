function sanitize(s) {
	var replacement = s.replace(/[&]/g, "&amp");
	replacement = replacement.replace(/[<]/g, "&lt");
	replacement = replacement.replace(/[>]/g, "&gt");
	replacement = replacement.replace(/["]/g, "&quot");
	replacement = replacement.replace(/[']/g, "&#x27");
	replacement = replacement.replace(/[/]/g, "&#x2F");
	return replacement;
}

function email_validity(s) {
	if (/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(s)) 
	{
		return true;
	}
	alert("You have entered an invalid email address!");
	return false;
}

function test_password(password) {
	if ((/[a-z]+/gi.test(password)) && (/[0-9]+/gi.test(password)) && (/[@._!()-+*^]+/.test(password)) && (! /[^a-zA-Z0-9@._!()-+*^]+/g.test(password))) {
		return true;
	}
	return false;
}

function input_sanitization() {
	var password = document.getElementById("reg_password").value;
	if (password != null) {
		if (test_password(password) == false) {
			alert('Invalid Password. Please conform to password policy');
			document.getElementById("reg_password").value = "";
			return false;
		}
	}
	
	else {
		alert('Please enter the password');
	}
	
	var confirm_password = document.getElementById("reg_confirm_password").value;
	if (confirm_password != null) {
		if (test_password(confirm_password) == false){
			document.getElementById("reg_confirm_password").value = "";
			alert('Invalid Confirm Password. Please conform to password policy');
			return false;
		}
	}
	
	else {
		alert('Please enter confirm password');
	}
	
	if(password != confirm_password){
		alert('The values in password and confirm password fields do not match. Please verify and try again');
		document.getElementById("reg_password").value = "";
		document.getElementById("reg_confirm_password").value = "";
		return false;
	}
	
	
	var arr = document.getElementsByClassName('validate_input');
	var replacement = null;
	if (arr.length > 0) {
		for (var x = 0; x < arr.length; x++) {
			replacement = sanitize(arr[x].value);
			document.getElementsByClassName('validate_input')[x].value = replacement;
		}
	}
	
	var arr1 = document.getElementsByClassName('validate_email');
	if (arr1.length > 0) {
		for (var x = 0; x < arr.length; x++) {
			if (email_validity(arr1[x].value) == false) { 
				alert('Invalid Email Address');
				return false;
			}
		}
	}
	return true;
}

