function sanitize(var s){
  var replacement = s.replace(/[|&;$%@"<>()+,]/g, "-");
  return replacement
}

function email_sanitize(var s){
  var email_replacement = s.replace(/([^a-z0-9@._]+)/gi, '_');
  return replacement
}

function input_sanitization() {
  var arr = document.getElementsByClassName('validate_input')
  var replacement = null
  for (var x = 0; x < arr.length; x++) {
     replacement = sanitize(arr[x])
     document.getElementsByClassName('validate_input')[x].value = replacement
  }
  var arr1 = document.getElementsByClassName('validate_email')
  var replacement = null
  for (var x = 0; x < arr.length; x++) {
     replacement = email_sanitize(arr1[x])
     document.getElementsByClassName('validate_email')[x].value = replacement
  }
  return True
}

function password_equal(){
  var password = document.getElementById("reg_password")
  var confirm_password = document.getElementById("reg_confirm_password")
  if(password != confirm_password){
    alert('The values in password and confirm password fields do not match. Please verify and try again')
    return False
  }
  return True
}
