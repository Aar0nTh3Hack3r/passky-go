package passky

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	//"golang.org/x/crypto/bcrypt"
)

var tokens = map[string]string{}

func encryptPassword(password string) string {
    // The password paramenter's length is 128 bytes, but
    // according to docs (https://pkg.go.dev/golang.org/x/crypto@v0.37.0/bcrypt#GenerateFromPassword)
    // > GenerateFromPassword does not accept passwords longer than 72 bytes,
    // > which is the longest password bcrypt will operate on.
    // The php implementation just cuts off the remaining bytes.
    // Proof:
    // php > var_dump(password_hash(str_repeat("a",72), PASSWORD_BCRYPT, [ 'cost' => 4, 'salt' => str_repeat('1', 22) ]));
    //  string(60) "$2y$04$111111111111111111111uhvWkzrhUTymuHpUJWWnjNVgi9W1iwIq"
    // php > var_dump(password_hash(str_repeat("a",73), PASSWORD_BCRYPT, [ 'cost' => 4, 'salt' => str_repeat('1', 22) ]));
    //  string(60) "$2y$04$111111111111111111111uhvWkzrhUTymuHpUJWWnjNVgi9W1iwIq"
    //
    // So I'm not doing anything with this function.
    // If the db gets leaked, the encrypted paswords gets leaked too with it.

	/*
    // Todo: calculate and store cost
	res, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}*/
	return password
}
func password_verify(password string, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(password), []byte(hash)) == 1
}
func GenerateToken(username string) string {
    // I realized, that the extention will automatically log out after (max) 1 h.
    // So I don't need to generate a long lasting session token :)

	/*mac := hmac.New(sha256.New, GetSecret())
	mac.Write([]byte(username))
	return hex.EncodeToString(mac.Sum(nil))*/

    str_token, ok := tokens[username]
    if ok {
        return str_token
    }

    token := make([]byte, TOKEN_LENGTH)
	if _, err := rand.Read(token); err != nil {
		panic(err)
	}
    str_token = hex.EncodeToString(token)
    tokens[username] = str_token
    return str_token
}
func IsTokenValid(username string, token string) bool {
	//return hmac.Equal([]byte(GenerateToken(username)), []byte(token))
    return subtle.ConstantTimeCompare([]byte(token), []byte(tokens[username])) == 1
}

func (pw *Password) IsPasswordConstentValid() int {
    return IsContentValid(pw.Website, pw.Username, pw.Password, pw.Message)
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
