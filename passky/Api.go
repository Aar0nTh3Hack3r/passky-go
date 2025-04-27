package passky

import (
	"log"
	"strings"
	"time"
)


func CreateAccount(username string, password string, email string) []byte{

	if GetMaxAccounts() > 0 {
		/*$amount_of_accounts = self::getUserCount();
		if($amount_of_accounts === -1) return Display::json(505);
		if($amount_of_accounts >= Settings::getMaxAccounts()) return Display::json(15);*/
	}

	if !preg_match(USERNAME_REGEX, username) {
		return Json(12)
	}
	if !preg_match(EMAIL_REGEX, email) || len(email) > 200 {
		return Json(6)
	}
	if !preg_match(PASSWORD_REGEX, password) {
		return Json(5)
	}

	username = strings.ToLower(username);
	email = strings.ToLower(email);
	encrypted_password := encryptPassword(password);

	switch IsUsernameTaken(username) {
		case 1:
			return Json(4);
		case 505:
			return Json(505);
	}

	maxPasswords := GetMaxPasswords();

	_, err := db.Exec("INSERT INTO users(username, email, password, max_passwords) VALUES(?, ?, ?, ?);",
		username, email, encrypted_password, maxPasswords,
	);
	if err != nil {
		log.Println(err)
		return Json(3)
	}
	user_cnt++
	
	return Json(0)
}

func GetToken(username string, password string, otp string) []byte{
	if(!preg_match(USERNAME_REGEX, username)) {
		return Json(12)
	}
	if(!preg_match(PASSWORD_REGEX, password)) {
		return Json(5)
	}
	username = strings.ToLower(username)

	user := new(User)

	switch UserfromUsername(username, user){
		case 1:
			return Json(1);
		case 505:
			return Json(505);
	}

	//if(self::is2FaValid($user->username, $otp, $user->secret, $user->yubico_otp) === 0) return Display::json(19);
	if !password_verify(password, user.Password) {
		return Json(2)
	}

	/*$cost = self::getHashingCost();
	if(password_needs_rehash($user->password, PASSWORD_BCRYPT, [ 'cost' => $cost ])) {
		$newPassword = self::encryptPassword($password);

		try{
			$conn = Settings::createConnection();

			Settings::removeLocalData($username . '_data', true);

			$stmt = $conn->prepare('UPDATE users SET password = :password WHERE username = :username');
			$stmt->bindParam(':username', $username, PDO::PARAM_STR);
			$stmt->bindParam(':password', $newPassword, PDO::PARAM_STR);
			$stmt->execute();
		}catch(PDOException $e) {}
		$conn = null;
	}*/

	/*$userID = $username . '-' . self::getUserIpAddress();
	$token = Settings::readLocalData('token_' . $userID, true);
	if($token === null) $token = Settings::readLocalData('token_' . $userID, false);
	if($token === null) $token = hash('sha256', self::generateCodes());
	Settings::writeLocalData('token_' . $userID, $token, 3_600, true);
	Settings::writeLocalData('token_' . $userID, $token, 3_600, false);*/

	today := time.Now()
	
	if _, err := db.Exec("UPDATE users SET accessed = ? WHERE username = ?", username, today); err != nil {
		log.Println(err)
	}

	JSON_OBJ := GetTokenResopnse{
		Token: GenerateToken(username),
		Auth: (user.Secret != nil),
		Max_passwords: user.Max_passwords,
	}
	/*if user.Yubico_otp != nil {
		yubico := string(user.Yubico_otp)
		JSON_OBJ.Yubico = &yubico
	}
	if user.Premium_expires != nil {
		expiration := string(user.Premium_expires)
		JSON_OBJ.Premium_expires = &expiration
	}*/

	passwords, err_code := GetPasswordsfromUsername(username)
	if err_code != 0 {
		return Json(err_code)
	}
	
	if len(passwords) > 0 {
		JSON_OBJ.Passwords = passwords
		return Json2(0, &JSON_OBJ)
	}
	return Json2(8, &JSON_OBJ)
}

func GetInfo() []byte {
	JSON_OBJ := GetInfoResopnse {
		Version: GetVersion(),
		Users: user_cnt,
		MaxUsers: GetMaxAccounts(),
		Passwords: password_cnt,
		MaxPasswords: GetMaxPasswords(),
		Location: GetLocation(),
		HashingCost: 0,
	}
	return Json2(0, &JSON_OBJ);
}

func SavePasswords(username string, token string, passwords []Password) []byte{
	if !preg_match(USERNAME_REGEX, username) {
		return Json(1)
	}
	username = strings.ToLower(username)
	if !IsTokenValid(username, token) {
		return Json(25)
	}

	user := new(User)
	switch UserfromUsername(username, user){
		case 1:
			return Json(1);
		case 505:
			return Json(505);
	}

	if(user.Max_passwords >= 0){
		/*$password_count = self::getUserPasswordCount($username);
		if($password_count === -1) return Display::json(505);
		if($password_count >= $user->max_passwords) return Display::json(16);*/
	}

	transaction, err := db.Begin()
	if err != nil {
		log.Println(err)
		return Json(505)
	}
	prepared, err := transaction.Prepare("INSERT INTO passwords(owner, website, username, password, message) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		log.Println(err)
		return Json(505)
	}

	valid_passwords := 0
	for _, pw := range passwords {
		if err_code := pw.IsPasswordConstentValid(); err_code != 0 {
			if len(passwords) == 1 {
				transaction.Rollback()
				return Json(err_code)
			}
			continue
		}
		valid_passwords++
		_, err := prepared.Exec(username, pw.Website, pw.Username, pw.Password, pw.Message)
		if err != nil {
			log.Println(err)
			transaction.Rollback()
			return Json(3)
		}
	}
	if err := transaction.Commit(); err != nil {
		log.Println(err)
		return Json(3)
	}

	password_cnt += valid_passwords

	JSON_OBJ := ImportPasswordsResopnse{
		Import_success: valid_passwords,
		Import_error: len(passwords) - valid_passwords,
	}

	return Json2(0, &JSON_OBJ)
}

func SavePassword(username string, token string, website string, username2 string, password2 string, message string) []byte{
	return SavePasswords(username, token, []Password{{
		Website: website,
		Username: username2,
		Password: password2,
		Message: message,
	}})
}

func GetPasswords(username string, token string) []byte{
	if !preg_match(USERNAME_REGEX, username) {
		return Json(1)
	}
	username = strings.ToLower(username)
	if !IsTokenValid(username, token) {
		return Json(25)
	}

	JSON_OBJ := GetPasswordsResopnse{}

	passwords, err_code := GetPasswordsfromUsername(username)
	if err_code != 0 {
		return Json(err_code)
	}

	if len(passwords) > 0{
		JSON_OBJ.Passwords = passwords
		return Json2(0, &JSON_OBJ)
	}
	return Json2(8, &JSON_OBJ)
}

func EditPassword(username string, token string, password_id int, website string, username2 string, password2 string, message string) []byte{
	if(!preg_match(USERNAME_REGEX, username)) {
		return Json(1)
	}
	username = strings.ToLower(username);
	if(!IsTokenValid(username, token)){
		return Json(25)
	}

	if err_code := IsContentValid(website, username2, password2, message); err_code != 0 {
		return Json(err_code)
	}

	res, err := db.Exec("UPDATE passwords SET website = ?, username = ?, password = ?, message = ? WHERE password_id = ? and owner = ?",
		website, username2, password2, message, password_id, username,
	)
	if err != nil {
		log.Println(err)
		return Json(13)
	}
	n, err := res.RowsAffected()
	if err != nil {
		log.Println(err)
		return Json(13)
	}
	if n < 1 {
		return Json(10)
	}
	return Json(0)
}

func DeletePasswords(username string, token string, password_id int, delete_account bool) []byte{
	// This function is 3 in 1:
	//  it is deletePassword,  when password_id >=  0 and delete_account == false
	//  it is deletePasswords, when password_id == -1 and delete_account == false
	//  it is deleteAccount,   when delete_account == true (in this case password_id will be ignored)
	if !preg_match(USERNAME_REGEX, username) {
		return Json(1)
	}
	username = strings.ToLower(username);
	if !IsTokenValid(username, token) {
		return Json(25)
	}
	if delete_account {
		password_id = -1
	}

	res, err := db.Exec("DELETE FROM passwords WHERE (? or password_id = ?) and owner = ?", 
		password_id == -1, password_id, username)
	if err != nil {
		log.Println(err)
		return Json(11)
	}
	n, err := res.RowsAffected()
	password_cnt -= int(n)
	if err != nil {
		log.Println(err)
		return Json(11)
	}
	if n < 1 && password_id != -1 {
		return Json(10)
	}

	if delete_account {
		_, err = db.Exec("DELETE FROM users WHERE username = ?", username)
		delete(tokens, username)
		if err != nil {
			log.Println(err)
			return Json(11)
		}
		user_cnt--
	}

	return Json(0)
}