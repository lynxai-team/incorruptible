// Copyright 2022-2025 Incorruptible contributors
// Incorruptible is a tiny+secured cookie token licensed under the MIT License.
// SPDX-License-Identifier: MIT

package incorruptible

import (
	"errors"
	"fmt"
	"net/http"
)

// Set is a middleware putting a "session" cookie when the request has no valid "incorruptible" token.
// The token is searched in the "session" cookie and in the first "Authorization" header.
// The "session" cookie (that is added in the response) contains a minimalist "incorruptible" token.
// Finally, Set stores the decoded token in the request context.
func (inc *Incorruptible) Set(next http.Handler) http.Handler {
	log.Securityf("Middleware Incorruptible.Set cookie %q MaxAge=%v setIP=%v",
		inc.cookie.Name, inc.cookie.MaxAge, inc.SetIP)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, a := inc.DecodeToken(r)
		if a != nil {
			// no valid token found => set a new token
			cookie, newDT, err := inc.NewCookie(r)
			if err != nil {
				log.S().Warning("Middleware IncorruptibleSet", err)
				return
			}
			http.SetCookie(w, cookie)
			tv = newDT
		}
		next.ServeHTTP(w, tv.ToCtx(r))
	})
}

// Chk is a middleware accepting requests only if it has a valid Incorruptible cookie,
// Chk does not consider the "Authorization" header (only the token within the cookie).
// Use instead the Vet() middleware to also verify the "Authorization" header.
// Chk finally stores the decoded token in the request context.
// In dev. mode, Chk accepts requests without valid cookie but does not store invalid tokens.
func (inc *Incorruptible) Chk(next http.Handler) http.Handler {
	log.Security("Middleware Incorruptible.Chk cookie only") // cookie DevMode=", inc.IsDev)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, err := inc.DecodeCookieToken(r)
		switch err {
		case nil: // OK: put the token in the request context
			r = tv.ToCtx(r)
		// case inc.IsDev:
		//	printErr("Chk DevMode no cookie", err)
		default:
			inc.writeErr(w, r, http.StatusUnauthorized, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

//nolint:unused // printErr is used in dev cycle (see above case inc.IsDev)
func printErr(str string, err error) {
	if doPrint {
		log.Debugf("Incorr.%s: %v", str, err)
	}
}

// Vet is a middleware accepting requests having a valid Incorruptible token
// either in the cookie or in the first "Authorization" header.
// Vet finally stores the decoded token in the request context.
// In dev. mode, Vet accepts requests without a valid token but does not store invalid tokens.
func (inc *Incorruptible) Vet(next http.Handler) http.Handler {
	log.Security("Middleware Incorruptible.Vet cookie/bearer") //  DevMode=", inc.IsDev)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tv, err := inc.DecodeToken(r)
		switch err {
		case nil:
			r = tv.ToCtx(r) // put the token in the request context
		// case !inc.IsDev:
		default:
			//	inc.writeErr(w, r, http.StatusUnauthorized, err...)
			//	return
		}
		next.ServeHTTP(w, r)
	})
}

func (inc *Incorruptible) DecodeToken(r *http.Request) (TValues, []any) {
	var tv TValues
	var err [2]error

	for i := 0; i < 2; i++ {
		var base91 string
		if i == 0 {
			base91, err[0] = inc.CookieToken(r)
		} else {
			base91, err[1] = inc.BearerToken(r)
		}
		if err[i] != nil {
			continue
		}
		if inc.equalMinimalistToken(base91) {
			return EmptyTValues(), nil
		}
		if tv, err[i] = inc.Decode(base91); err[i] != nil {
			continue
		}
		if err[i] = tv.Valid(r); err[i] != nil {
			continue
		}
		return tv, nil
	}

	return tv, []any{
		fmt.Errorf("missing or invalid 'incorruptible' token in either "+
			"the '%s' cookie or the 1st 'Authorization' header", inc.cookie.Name),
		"error_cookie", err[0],
		"error_bearer", err[1],
	}
}

func (inc *Incorruptible) DecodeCookieToken(r *http.Request) (TValues, error) {
	base91, err := inc.CookieToken(r)
	if err != nil {
		return TValues{}, err
	}
	if inc.equalMinimalistToken(base91) {
		return EmptyTValues(), nil
	}
	tv, err := inc.Decode(base91)
	if err != nil {
		return tv, err
	}
	return tv, tv.Valid(r)
}

func (inc *Incorruptible) DecodeBearerToken(r *http.Request) (TValues, error) {
	base91, err := inc.BearerToken(r)
	if err != nil {
		return TValues{}, err
	}
	if inc.equalMinimalistToken(base91) {
		return EmptyTValues(), nil
	}
	tv, err := inc.Decode(base91)
	if err != nil {
		return tv, err
	}
	return tv, tv.Valid(r)
}

// CookieToken returns the token (in base91 format) from the cookie.
func (inc *Incorruptible) CookieToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(inc.cookie.Name)
	if err != nil {
		return "", err
	}

	// TODO: Add other verifications, but do not break specific usages.
	// if !cookie.HttpOnly {
	// 	return "", errors.New("no HttpOnly cookie")
	// }
	// if cookie.SameSite != s.cookie.SameSite {
	// 	return "", fmt.Errorf("want cookie SameSite=%v but got %v", s.cookie.SameSite, cookie.SameSite)
	// }
	// if cookie.Secure != s.cookie.Secure {
	// 	return "", fmt.Errorf("want cookie Secure=%v but got %v", s.cookie.Secure, cookie.Secure)
	// }

	return trimTokenScheme(cookie.Value)
}

// BearerToken returns the token (in base91 format) from the HTTP Authorization header.
func (inc *Incorruptible) BearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("no 'Authorization: " + prefixScheme + "xxxxxxxx' in the request header")
	}

	return trimBearerScheme(auth)
}

func trimTokenScheme(uri string) (string, error) {
	const schemeSize = len(tokenScheme)
	if len(uri) < schemeSize+Base91MinSize {
		return "", fmt.Errorf("token URI too short: %d < %d", len(uri), schemeSize+Base91MinSize)
	}
	if uri[:schemeSize] != tokenScheme {
		return "", fmt.Errorf("want token URI in format '"+tokenScheme+"xxxxxxxx' got len=%d", len(uri))
	}
	tokenBase91 := uri[schemeSize:]
	return tokenBase91, nil
}

func trimBearerScheme(auth string) (string, error) {
	const prefixSize = len(prefixScheme)
	if len(auth) < prefixSize+Base91MinSize {
		return "", fmt.Errorf("bearer too short: %d < %d", len(auth), prefixSize+Base91MinSize)
	}
	if auth[:prefixSize] != prefixScheme {
		return "", fmt.Errorf("want format '"+prefixScheme+"xxxxxxxx' got len=%d", len(auth))
	}
	tokenBase91 := auth[prefixSize:]
	return tokenBase91, nil
}
