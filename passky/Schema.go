package passky

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

var db *sql.DB
var user_cnt, password_cnt int

type User struct {
	User_id int64
    Username string
    Email string
    Password string
    Secret []byte // 2fa_secret
    Yubico_otp []byte
    Backup_codes []byte
    Max_passwords int64
    Premium_expires []byte
    Created time.Time
    Accessed time.Time
}
type Password struct {
    Password_id int64 `json:"id"`
    Owner string `json:"-"`
    Website string `json:"website"`
    Username string `json:"username"`
    Password string `json:"password"`
    Message string `json:"message"`
}

func UserfromUsername(username string, user *User) int {
    var err error
    if user == nil {
        var user_id int64
        err = db.QueryRow("SELECT user_id FROM users WHERE username = ?", username).Scan(&user_id)
    } else {
        err = db.QueryRow("SELECT * FROM users WHERE username = ?", username).Scan(
            &user.User_id, &user.Username, &user.Email, &user.Password, &user.Secret, &user.Yubico_otp, &user.Backup_codes, &user.Max_passwords, &user.Premium_expires, &user.Created, &user.Accessed,
        )
    }
    if err != nil {
        if err == sql.ErrNoRows {
			return 1
		}
        log.Println(err)
        return 505
    }
    return 0
}
func GetPasswordsfromUsername(username string) ([]Password, int) {
    rows, err := db.Query("SELECT password_id AS id, website, username, password, message FROM passwords WHERE owner = ?", username);
	if err != nil {
		log.Println(err)
		return nil, 505
	}

	var passwords []Password
	for rows.Next() {
		var passwd = Password{}
		if err := rows.Scan(&passwd.Password_id, &passwd.Website, &passwd.Username, &passwd.Password, &passwd.Message); err != nil {
			log.Println(err)
			return nil, 505
		}
		passwords = append(passwords, passwd)
	}
    return passwords, 0
}

func InitDB() error {
	var err error
    db, err = sql.Open("sqlite", DB_NAME)
	if err != nil {
		return err
	}

    _, err = db.Exec(`
    -- Created: 10/01/2023
    -- Modified: 10/01/2023
    -- Author: Abdelaziz Elrashed <aeemh.sdn@gmail.com>
    -- Database: SQLite

    -- Create tables section -------------------------------------------------

    -- Table users

    CREATE TABLE IF NOT EXISTS "users"
    (
        "user_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "username" VARCHAR(30) NOT NULL,
        "email" VARCHAR(255) NOT NULL,
        "password" VARCHAR(255) NOT NULL,
        "2fa_secret" VARCHAR(20),
        "yubico_otp" VARCHAR(64),
        "backup_codes" VARCHAR(69),
        "max_passwords" Int NOT NULL DEFAULT 1000,
        "premium_expires" Date,
        "created" Date NOT NULL DEFAULT (CURRENT_DATE),
        "accessed" Date NOT NULL DEFAULT (CURRENT_DATE),
        UNIQUE ("username")
    );

    -- Table passwords

    CREATE TABLE IF NOT EXISTS "passwords"
    (
        "password_id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "owner" VARCHAR(30) NOT NULL,
        "website" VARCHAR(255) NOT NULL,
        "username" VARCHAR(255) NOT NULL,
        "password" VARCHAR(255) NOT NULL,
        "message" VarChar(10000) NOT NULL
    );

    -- Table licenses

    CREATE TABLE IF NOT EXISTS "licenses"
    (
        "license" VARCHAR(30) NOT NULL PRIMARY KEY,
        "duration" Int NOT NULL DEFAULT 365,
        "created" Date NOT NULL DEFAULT (CURRENT_DATE),
        "used" Date,
        "linked" VARCHAR(30) DEFAULT NULL
    );

    CREATE INDEX IF NOT EXISTS "owner_idx" ON "passwords" ("owner");
`)
	if err != nil {
		return err
	}

    if err := db.QueryRow("SELECT COUNT(1) FROM users").Scan(&user_cnt); err != nil {
        return err
    }
    if err := db.QueryRow("SELECT COUNT(1) FROM passwords").Scan(&password_cnt); err != nil {
        return err
    }

	return nil
}