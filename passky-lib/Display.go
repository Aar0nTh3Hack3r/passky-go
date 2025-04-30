package passky

import (
	"encoding/json"
	"reflect"
	"regexp"
)

type ErrorResponse struct {
	Error int `json:"error"`
	Info string `json:"info"`
}
type GetPasswordsResopnse struct {
	ErrorResponse
	Passwords []Password `json:"passwords,omitempty"`
}
type GetTokenResopnse struct {
	GetPasswordsResopnse
	Token string `json:"token"`
	Auth bool `json:"auth"`
	Yubico *string `json:"yubico"`
	Max_passwords int64 `json:"max_passwords"`
	Premium_expires *string `json:"premium_expires"`}
type GetInfoResopnse struct {
	ErrorResponse
	Version string `json:"version"`
	Users int `json:"users"`
	MaxUsers int `json:"maxUsers"`
	Passwords int `json:"passwords"`
	MaxPasswords int `json:"maxPasswords"`
	Location string `json:"location"`
	HashingCost int `json:"hashingCost"`
}
type ImportPasswordsResopnse struct {
	ErrorResponse
	Import_success int `json:"import_success"`
	Import_error int `json:"import_error"`
}

func Json2(error_code int, JSON_OBJ interface{}) []byte {
	if JSON_OBJ == nil {
		JSON_OBJ = new(ErrorResponse)
	}
	v := reflect.ValueOf(JSON_OBJ).Elem()
	v.FieldByName("Error").SetInt(int64(error_code))
	v.FieldByName("Info").SetString(GetError(error_code))
	res, err := json.Marshal(JSON_OBJ)
	if err != nil {
		panic(err)
	}
	return res
}
func Json(error_code int) []byte {
	return Json2(error_code, nil)
}

func preg_match(pattern string, subject string) bool {
	matched, err := regexp.Match(pattern, []byte(subject))
	if err != nil {
		panic(err)
	}
	return matched
}