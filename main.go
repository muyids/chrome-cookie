package chrome_cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/havoc-io/go-keytar"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"
)

var (
	SALT       = "saltysalt"
	ITERATIONS = 1003
	KEYLENGTH  = 16
)

func getDerivedKey() []byte {
	keychain, err := keytar.GetKeychain()
	if err != nil {
		panic(err)
	}
	chromePassword, err := keychain.GetPassword("Chrome Safe Storage", "Chrome")
	if err != nil {
		panic(err)
	}
	dk := pbkdf2.Key([]byte(chromePassword), []byte(SALT), ITERATIONS, KEYLENGTH, sha1.New)
	return dk
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// Decryption based on http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
// Inspired by https://www.npmjs.org/package/chrome-cookies
func chromeDecrypt(key []byte, encrypted []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		iv[i] = ' '
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData = pkcs5UnPadding(origData)
	return string(origData), nil
}

func connDB(profile string) *sql.DB {
	if "" == profile {
		profile = "Profile 1"
	}

	user, err := user.Current()
	home := user.HomeDir
	if nil != err {
		log.Fatal(err)
	}
	dbFile := home + "/Library/Application Support/Google/Chrome/" + profile + "/Cookies"

	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func GetCookie(path, profile, format string) ([]*http.Cookie, error) {

	db := connDB(profile)
	defer db.Close()

	derivedKey := getDerivedKey()

	u, err := url.Parse(path)
	if nil != err {
		panic("Could not parse domain from URI, format should be http://www.example.com/path/")
	}

	sqlFmt := "SELECT name, value, path, host_key, expires_utc, is_secure, is_httponly, samesite, encrypted_value " +
		"FROM cookies " +
		"where host_key like '%" + u.Hostname() + "' ORDER BY LENGTH(path) DESC, creation_utc ASC"

	rows, err := db.Query(sqlFmt)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	cookies := make([]*http.Cookie, 0)
	for rows.Next() {
		name, value, path, domain, expiresUtc, isSecure, isHttponly := "", "", "", "", "", false, false
		samesite := http.SameSite(0)
		encryptedValue := make([]byte, 0)
		err = rows.Scan(&name, &value, &path, &domain, &expiresUtc, &isSecure, &isHttponly, &samesite, &encryptedValue)

		cookie := &http.Cookie{
			Name:       name,
			Value:      value,
			Path:       path,
			Domain:     domain,
			Expires:    convertChromiumTimestampToUnix(expiresUtc),
			RawExpires: expiresUtc,
			MaxAge:     0,
			Secure:     isSecure,
			HttpOnly:   isHttponly,
			SameSite:   samesite,
			Raw:        "",
			Unparsed:   nil,
		}

		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		if len(encryptedValue) > 0 {
			cookie.Value, err = chromeDecrypt(derivedKey, encryptedValue[3:])
			if nil != err {
				log.Fatal(err)
				return nil, err
			}
		}
		cookies = append(cookies, cookie)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	if format != "" {
		output := ""
		switch format {
		case "curl":
			output = convertRawToNetscapeCookieFileFormat(cookies, u.Hostname())
			break
		case "set-cookie":
			output = convertRawToSetCookie(cookies)
			break
		case "header":
			output = convertToHeader(cookies)
			break
		case "puppeteer":
			output = convertRawToPuppeteerState(cookies)
			break
		case "json":
			output = convertRawToJson(cookies)
			break
		default:
			fmt.Println("format not support")
		}
		fmt.Fprintln(os.Stdout, output)
	}
	return cookies, nil
}

// Chromium stores its timestamps in sqlite on the Mac using the Windows Gregorian epoch
// https://github.com/adobe/chromium/blob/master/base/time_mac.cc#L29
// This converts it to a UNIX timestamp
func convertChromiumTimestampToUnix(timestamp string) time.Time {
	r, err := strconv.Atoi(timestamp)
	if nil != err {
		panic(err)
	}
	if r == 0 {
		return time.Unix(int64(0), int64(0))
	}
	return time.Unix(int64((r-11644473600000000)/1000000), int64(0))
}

func convertRawToNetscapeCookieFileFormat(cookies []*http.Cookie, domain string) string {
	out := ""
	for _, cookie := range cookies {
		out += cookie.Domain + "\t"

		if cookie.Domain == "."+domain {
			out += "TRUE\t"
		} else {
			out += "FALSE\t"
		}
		out += cookie.Path + "\t"
		if cookie.Secure {
			out += "TRUE" + "\t"
		} else {
			out += "FALSE" + "\t"
		}

		if cookie.RawExpires != "" {
			out += strconv.Itoa(int(cookie.Expires.Unix())) + "\t"
		} else {
			out += "0\t"
		}
		out += cookie.Name + "\t"
		out += cookie.Value + "\t"
		out += "\n"
	}
	return out
}

func convertToHeader(cookies []*http.Cookie) string {
	headers := make([]string, 0)
	for _, cookie := range cookies {
		headers = append(headers, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(headers, "; ")
}

func convertRawToSetCookie(cookies []*http.Cookie) string {
	output := "[\n"
	for _, cookie := range cookies {
		row := make([]string, 0)
		row = append(row, cookie.Name+"="+cookie.Value)
		row = append(row, "expires="+cookie.Expires.String())
		row = append(row, "domain="+cookie.Domain)
		row = append(row, "path="+cookie.Path)
		if cookie.Secure {
			row = append(row, "Secure")
		}
		if cookie.HttpOnly {
			row = append(row, "HttpOnly")
		}
		output = output + "  '" + strings.Join(row, "; ") + "',\n"
	}
	output += "]"
	return output
}

func convertRawToJson(cookies []*http.Cookie) string {
	m := make(map[string]string, 0)
	for _, cookie := range cookies {
		m[string(cookie.Name)] = string(cookie.Value)
	}
	j, _ := json.MarshalIndent(m, "", "    ")
	return string(j)
}

func convertRawToPuppeteerState(cookies []*http.Cookie) string {
	type Puppeteer struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		Expires  string `json:"expires"`
		Domain   string `json:"domain"`
		Path     string `json:"path"`
		Secure   bool   `json:"secure,omitempty"`
		HttpOnly bool   `json:"http_only,omitempty"`
	}
	r := make([]*Puppeteer, 0)
	for _, cookie := range cookies {
		p := &Puppeteer{
			Name:    cookie.Name,
			Value:   cookie.Value,
			Expires: cookie.Expires.String(),
			Domain:  cookie.Domain,
			Path:    cookie.Path,
		}
		if cookie.Secure {
			p.Secure = true
		}
		if cookie.HttpOnly {
			p.HttpOnly = true
		}
		r = append(r, p)
	}
	j, err := json.MarshalIndent(r, "", "    ")
	if nil != err {
		panic(err)
	}
	return string(j)
}
