package passky

const DB_NAME = "passky.db"
const TOKEN_LENGTH = 32

const USERNAME_REGEX = "(?i)^[a-z0-9._]{2,30}$" // modified to be 2 - 30 not 6 - 30
const EMAIL_REGEX = "(?i)^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z0-9-]{2,}$"
const PASSWORD_REGEX = "(?i)^[a-z0-9]{128}$"


func GetVersion() string {
	return "0.0.2"
}

func GetMaxAccounts() int {
	return -1
}

func GetMaxPasswords() int {
	return -1
}

func GetLocation() string{
	return "RO";
}
