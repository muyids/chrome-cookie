# chrome-cookies

Extract encrypted Google Chrome cookies for a url on Mac OS X 

## Installation

```
go get github.com/muyids/chrome-cookie
```

## API

GetCookie(url, profile, format string) 

---------------------------------

- `url` should be a fully qualified url, e.g. `http://www.example.com/path/`
- `profile` default "", should be your cookies file location, e.g. `Profile 1` 
- `format` default "", is optional and can be one of the following values:

format | description
------------ | -------------
curl | [Netscape HTTP Cookie File](http://curl.haxx.se/docs/http-cookies.html) contents usable by curl and wget
set-cookie | Array of Set-Cookie header values
header | `cookie` header string, similar to what a browser would send
puppeteer | an array of objects that can be loaded directly into puppeteer setCookie(...) for testing
object | (default) Object where key is the cookie name and value is the cookie value. These are written in order so it's possible that duplicate cookie names will be overriden by later values

If `format` is not specified, will not printf.

Cookie order tries to follow [RFC 6265 - Section 5.4, step 2](http://tools.ietf.org/html/rfc6265#section-5.4) as best as possible.

## Examples

basic usage
-----------

```cgo
import (
    "github.com/muyids/chrome-cookie"
)

func main() {
    chrome_cookie.GetCookie("https://github.com/muyids", "", "json")
}
```

## Limitations

On OS X, this module requires Keychain Access to read the Google Chrome encryption key. The first time you use it, it will popup this dialog:

![image](https://raw.githubusercontent.com/muyids/godvein.github.io/master/static/warn.png)

The SQLite database that Google Chrome stores its cookies is only persisted to every 30 seconds or so, so this can explain while you'll see a delay between which cookies your browser has access to and this module.


