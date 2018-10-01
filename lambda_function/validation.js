exports.validateUsername = function(username, errors){
    if (!username) {
        errors.push("Missing username");
    } else if (username.length < 3) {
        errors.push("Username must be at least 3 characters");
    } else if (username.indexOf("@")!= -1) {
        errors.push("Username may not contain an '@' sign");
    }
}

exports.validatePasswordHash = function(passwordHash, errors){
	if (!passwordHash) {
        errors.push("Missing password");
	}
}

exports.validateEmail = function(email, errors){
	if (!email) {
        errors.push("Missing email");
	} else if (!email.toLowerCase().endsWith("@georgiasouthern.edu")) {
        errors.push("Not a Georgia Southern email address");
	}
}

exports.validateRegistrationCode = function(registrationcode, errors){
	if (!registrationcode) {
        errors.push("Missing registrationcode");
	} 
}