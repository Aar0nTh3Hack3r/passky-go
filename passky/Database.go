package passky

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	//"golang.org/x/crypto/bcrypt"
)

func encryptPassword(password string) string {
	// Todo: calculate and store cost
	/*res, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}*/
	return password
}
func password_verify(password string, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(password), []byte(hash)) == 1
}
func GenerateToken(username string) string {
	mac := hmac.New(sha256.New, GetSecret())
	mac.Write([]byte(username))
	return hex.EncodeToString(mac.Sum(nil))
}
func IsTokenValid(username string, token string) bool {
	return hmac.Equal([]byte(GenerateToken(username)), []byte(token))
}

func IsContentValid(website string, username2 string, password2 string, message string) int {
	if !(len(website) >= 36   && len(website) <= 255)    || strings.Contains(website, " ") {return (300)}
	if !(len(username2) >= 36 && len(username2) <= 255)  || strings.Contains(username2, " ") {return (301)}
	if !(len(password2) >= 36 && len(password2) <= 255)  || strings.Contains(password2, " ") {return (302)}
	if !(len(message) >= 36   && len(message) <= 10_000) || strings.Contains(message, " ") {return (303)}
	return 0
}

func IsUsernameTaken(username string) int {
	switch UserfromUsername(username, nil) {
		case 1:
			return 0
		case 0:
			return 1
	}
	return 505
}
