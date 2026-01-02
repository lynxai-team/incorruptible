// Copyright 2022-2025 Incorruptible contributors
// Incorruptible is a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"crypto/cipher"
	crand "crypto/rand"
	"math/rand/v2"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/LynxAIeu/emo"
	baseN "github.com/mtraver/base91"
)

//nolint:gochecknoglobals // global logger
var log = emo.NewZone("inc")

type Incorruptible struct {
	writeErr WriteErr
	SetIP    bool // If true => put the remote IP in the token.
	cookie   http.Cookie
	cipher   cipher.AEAD
	magic    byte
	baseN    *baseN.Encoding
	rand     *rand.ChaCha8
}

const (
	authScheme   = "Bearer "
	tokenScheme  = "i:" // See RFC 8959, here "i" means "incorruptible token format"
	prefixScheme = authScheme + tokenScheme
)

// New creates a new Incorruptible. This function is designed to be easily used by github.com/LynxAIeu/garcon
// Thus the parameters order is consistent with gc.NewJWTChecker, using gc.Writer as first parameter.
// Please share your thoughts/feedback: we are unsure if this is a good idea... we can change it :-)
func New(writeErr WriteErr, urls []*url.URL, secretKey []byte, cookieName string, maxAge int, setIP bool) *Incorruptible {
	if writeErr == nil {
		writeErr = defaultWriteErr
	}

	if len(urls) == 0 {
		log.Panic("No URL => Cannot set cookie attributes: Domain, Secure and Path")
	}

	secure, dns, dir := extractMainDomain(urls[0])

	cipher := NewCipher(secretKey)

	// reproducible random generator using the secret as seed
	var seed [32]byte
	copy(seed[:], secretKey)
	randGen := rand.NewChaCha8(seed)
	magic := byte(randGen.Uint64())
	// randomize order of the input string.
	runes := []rune(noSpaceDoubleQuoteSemicolon)
	for i := uint(len(runes) - 1); i > 0; i-- {
		j := uint(randGen.Uint64()) % (i + 1)
		runes[i], runes[j] = runes[j], runes[i]
	}
	encodingAlphabet := string(runes)

	// reset the random generator with a strong random seed
	_, err := crand.Read(seed[:])
	if err != nil {
		log.Panic("crypto/rand.Read err=", err)
	}

	inc := Incorruptible{
		writeErr: writeErr,
		SetIP:    setIP,
		cookie:   newCookie(cookieName, secure, dns, dir, maxAge),
		cipher:   cipher,
		magic:    magic,
		baseN:    baseN.NewEncoding(encodingAlphabet),
		rand:     rand.NewChaCha8(seed),
	}

	inc.addMinimalistToken()

	log.Securityf("Cookie %s Domain=%v Path=%v Max-Age=%v Secure=%v SameSite=%v HttpOnly=%v Value=%d bytes",
		inc.cookie.Name, inc.cookie.Domain, inc.cookie.Path, inc.cookie.MaxAge,
		inc.cookie.Secure, inc.cookie.SameSite, inc.cookie.HttpOnly, len(inc.cookie.Value))

	return &inc
}

func (inc *Incorruptible) addMinimalistToken() {
	if !inc.useMinimalistToken() {
		return
	}

	// serialize a minimalist token
	// including encryption and Base91-encoding
	token, err := inc.Encode(EmptyTValues())
	if err != nil {
		log.Panic(err)
	}

	// insert this generated token in the cookie
	inc.cookie.Value = tokenScheme + token
}

// NewCookie creates a new cookie based on default values.
// the HTTP request parameter is used to get the remote IP (only when inc.SetIP is true).
func (inc *Incorruptible) NewCookie(r *http.Request, keyValues ...KVal) (*http.Cookie, TValues, error) {
	cookie := inc.cookie // local copy of the default cookie

	tv, err := inc.NewTValues(r)
	if err != nil {
		return &cookie, tv, err
	}

	if !inc.useMinimalistToken() || (len(keyValues) > 0) {
		err := tv.Set(keyValues...)
		if err != nil {
			return &cookie, tv, err
		}

		token, err := inc.Encode(tv)
		if err != nil {
			return &cookie, tv, err
		}

		cookie.Value = tokenScheme + token
	}

	return &cookie, tv, nil
}

func (inc *Incorruptible) NewTValues(r *http.Request, keyValues ...KVal) (TValues, error) {
	var tv TValues

	if !inc.useMinimalistToken() {
		tv.SetExpiry(inc.cookie.MaxAge)
		if inc.SetIP {
			err := tv.SetRemoteIP(r)
			if err != nil {
				return tv, err
			}
		}
	}

	err := tv.Set(keyValues...)
	return tv, err
}

func (inc *Incorruptible) NewCookieFromValues(tv TValues) (*http.Cookie, error) {
	token, err := inc.Encode(tv)
	if err != nil {
		return &inc.cookie, err
	}
	cookie := inc.NewCookieFromToken(token, tv.MaxAge())
	return cookie, nil
}

func (inc *Incorruptible) NewCookieFromToken(token string, maxAge int) *http.Cookie {
	cookie := inc.cookie
	cookie.Value = tokenScheme + token
	cookie.MaxAge = maxAge
	return &cookie
}

// DeadCookie returns an Incorruptible cookie without Value and with "Max-Age=0"
// in order to delete the Incorruptible cookie in the current HTTP session.
//
// Example:
//
//	func logout(w http.ResponseWriter, r *http.Request) {
//	    http.SetCookie(w, Incorruptible.DeadCookie())
//	}
func (inc *Incorruptible) DeadCookie() *http.Cookie {
	cookie := inc.cookie // local copy of the default cookie
	cookie.Value = ""
	cookie.MaxAge = -1 // MaxAge<0 means "delete cookie now"
	return &cookie
}

// Cookie returns a pointer to the default cookie values.
// This can be used to customize some cookie values (may break),
// and also to facilitate testing.
func (inc *Incorruptible) Cookie(_ int) *http.Cookie {
	return &inc.cookie
}

func (inc *Incorruptible) CookieName() string {
	return inc.cookie.Name
}

// URL schemes.
const (
	HTTP  = "http"
	HTTPS = "https"
)

func (inc *Incorruptible) useMinimalistToken() bool {
	return (inc.cookie.MaxAge <= 0) && (!inc.SetIP)
}

// equalMinimalistToken compares with the default token.
func (inc *Incorruptible) equalMinimalistToken(base91 string) bool {
	const schemeSize = len(tokenScheme) // to skip the token scheme
	return inc.useMinimalistToken() && (base91 == inc.cookie.Value[schemeSize:])
}

//nolint:nonamedreturns // we want to document the returned values.
func extractMainDomain(u *url.URL) (secure bool, dns, dir string) {
	if u == nil {
		log.Panic("No URL => Cannot set Cookie domain")
	}

	switch u.Scheme {
	case HTTP:
		secure = false
	case HTTPS:
		secure = true
	default:
		log.Panicf("Unexpected protocol scheme in %+v", u)
	}

	return secure, u.Hostname(), u.Path
}

// This function was used to trigger the dev. mode
// func isLocalhost(urls []*url.URL) bool {
// 	if len(urls) > 0 && urls[0].Scheme == "http" {
// 		host, _, _ := net.SplitHostPort(urls[0].Host)
// 		if host == "localhost" {
// 			log.Security("DevMode accepts missing/invalid token from", urls[0])
// 			return true
// 		}
// 	}
//
// 	log.Security("ProdMode requires valid token: no http://localhost in first of", urls)
// 	return false
// }

func newCookie(name string, secure bool, dns, dir string, maxAge int) http.Cookie {
	dir = path.Clean(dir)
	if dir == "." {
		dir = "/"
	}

	if name == "" {
		name = "session"
		for i := len(dir) - 2; i >= 0; i-- {
			if dir[i] == byte('/') {
				name = dir[i+1:]
				break
			}
		}
	}

	// cookie prefix for enhanced security
	if secure && name[0] != '_' {
		if dir == "/" {
			// "__Host-" when cookie has "Secure" flag, has no "Domain",
			// has "Path=/" and is sent from a secure origin.
			dns = ""
			name = "__Host-" + name
		} else {
			// "__Secure-" when cookie has "Secure" flag and is sent from a secure origin
			// "__Host-" is better than the "__Secure-" prefix.
			name = "__Secure-" + name
		}
	}

	// sameSite = Strict works when using two backends like:
	// localhost:3000 (node) and localhost:8080 (API)
	// https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite
	const sameSite = http.SameSiteStrictMode

	return http.Cookie{
		Name:       name,
		Value:      "", // emptyCookie because no token
		Path:       dir,
		Domain:     dns,
		Expires:    time.Time{},
		RawExpires: "",
		MaxAge:     maxAge,
		Secure:     secure,
		HttpOnly:   true,
		SameSite:   sameSite,
		Raw:        "",
		Unparsed:   nil,
	}
}
