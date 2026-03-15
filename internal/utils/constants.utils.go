package utils

var DefaultPasswordCharset = struct {
	SMALL   string
	BIG     string
	NUMBER  string
	SPECIAL string
}{
	SMALL   : "abcdefghijklmnopqrstuvwxyz",
	BIG     : "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	NUMBER : "0123456789",
	SPECIAL : "!@#$%&*()=[]|;?",
}

var CROCKFORD_BASE32 = []byte("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

var USERNAME_SET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
var PASSWORD_SET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*()=[]|;?"