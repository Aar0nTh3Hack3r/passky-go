package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"passky/passky"
	"strconv"
	"strings"
)

func main() {
    if err := passky.InitDB(); err != nil {
        log.Fatal(err)
    }
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        r.ParseMultipartForm(2 << 20 /* 2 MB */)
        log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

        r.Header.Set("Content-Security-Policy", "default-src \"none\"; frame-ancestors \"none\"; object-src \"none\"; base-uri \"none\"; require-trusted-types-for \"script\"; form-action \"none\"")
        r.Header.Set("X-Content-Type-Options", "nosniff");
        r.Header.Set("X-XSS-Protection", "1; mode=block");
        r.Header.Set("X-Frame-Options", "DENY");
        r.Header.Set("Referrer-Policy", "no-referrer");
        r.Header.Set("Permissions-Policy", "interest-cohort=()");
        r.Header.Set("Content-Type", "application/json; charset=utf-8");
        r.Header.Set("Access-Control-Allow-Origin", "*");
        r.Header.Set("Access-Control-Allow-Credentials", "true");
        r.Header.Set("Access-Control-Max-Age", "86400");

        /*if r.Method == "OPTIONS" {
            if(isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            if(isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
            return
        }*/
        
        var user, password string
        if auth := r.Header.Get("Authorization"); auth != "" {
            auths := strings.Split(auth, " ")
            if len(auths) != 2 {
                w.WriteHeader(400)
                return
            }
            decoded, err := base64.StdEncoding.DecodeString(auths[1])
            if err != nil {
                log.Println(err)
                w.WriteHeader(400)
                return
            }
            fmt.Println(auth)
            auths = strings.Split(string(decoded), ":")
            if len(auths) != 2 {
                w.WriteHeader(400)
                return
            }
            user = auths[0]
            password = auths[1]
        }
        var out []byte
        switch r.URL.Query().Get("action") {
            case "getInfo":
                out=(passky.GetInfo())
                break
            case "getToken":
                out=(passky.GetToken(user, password, r.FormValue("otp")))
                break
            case "createAccount":
                out=(passky.CreateAccount(user, password, r.FormValue("email")))
                break
            case "savePassword":
                out=(passky.SavePassword(user, password, r.FormValue("website"), r.FormValue("username"), r.FormValue("password"), r.FormValue("message")))
                break
            case "getPasswords":
                out=(passky.GetPasswords(user, password))
                break
            case "editPassword":
                password_id, err := strconv.Atoi(r.FormValue("password_id"))
                if err != nil {
                    log.Println(err)
                    w.WriteHeader(400)
                    return
                }
                out=(passky.EditPassword(user, password, password_id, r.FormValue("website"), r.FormValue("username"), r.FormValue("password"), r.FormValue("message")))
                break
            case "importPasswords":
                decoder := json.NewDecoder(r.Body)
                var passwords []passky.Password
                if err := decoder.Decode(&passwords); err != nil {
                    log.Println(err)
                    out=(passky.Json(14))
                    break
                }
                fmt.Println(passwords)
                out=(passky.SavePasswords(user, password, passwords))
                break
            case "deletePassword":
                password_id, err := strconv.Atoi(r.FormValue("password_id"))
                if err != nil {
                    log.Println(err)
                    w.WriteHeader(400)
                    return
                }
                if password_id < 0 {
                    out=(passky.Json(10))
                    break
                }
                out=(passky.DeletePasswords(user, password, password_id, false))
                break
            case "deletePasswords":
                out=(passky.DeletePasswords(user, password, -1, false))
                break
            case "deleteAccount":
                out=(passky.DeletePasswords(user, password, -1, true))
                break
            default:
                out=(passky.Json(401))
        }
        fmt.Println(string(out))
        w.Write(out)
    })
    fmt.Println("Listening on port 9090")
    http.ListenAndServe(":9090", nil)
}
