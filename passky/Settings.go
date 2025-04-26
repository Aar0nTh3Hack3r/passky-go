package passky

import (
	"crypto/rand"
	"os"
)

const DB_NAME = "passky.db"
const SECRET_FILE_NAME = "secret.key"
const SECRET_KEY_LENGTH = 64

const USERNAME_REGEX = "(?i)^[a-z0-9._]{2,30}$"
const EMAIL_REGEX = "(?i)^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z0-9-]{2,}$"
const PASSWORD_REGEX = "(?i)^[a-z0-9]{128}$"


func GetVersion() string {
	return "0.0.1"
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

func GetSecret() []byte {
	key, err := os.ReadFile(SECRET_FILE_NAME)
	if err != nil {
		if os.IsNotExist(err) {
			key = make([]byte, SECRET_KEY_LENGTH)
			if _, err := rand.Read(key); err != nil {
				panic(err)
			}
			if err := os.WriteFile(SECRET_FILE_NAME, key, 0o600); err != nil {
				panic(err)
			}
			return key
		}
		panic(err)
	}
	return key
}