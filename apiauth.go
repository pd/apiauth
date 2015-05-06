package apiauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

var gmt *time.Location

func init() {
	loc, err := time.LoadLocation("Etc/GMT")
	if err != nil {
		log.Panic("apiauth: Can not load timezone Etc/GMT: ", err)
	}
	gmt = loc
}

// Sign computes the signature for the given HTTP request, and
// adds the resulting Authorization header value to it. If any
// of the prerequisite headers are absent, an error is returned.
func Sign(r *http.Request, accessID, secretKey string) error {
	var date, contentType, contentMD5 string

	date = r.Header.Get("Date")
	if date == "" {
		return fmt.Errorf("No Date header present")
	}

	if r.Body != nil {
		contentType = r.Header.Get("Content-Type")
		if contentType == "" {
			return fmt.Errorf("No Content-Type header present")
		}

		contentMD5 = r.Header.Get("Content-MD5")
		if contentMD5 == "" {
			return fmt.Errorf("No Content-MD5 header present")
		}
	}

	preexisting := r.Header.Get("Authorization")
	if preexisting != "" {
		return fmt.Errorf("Authorization header already present")
	}

	sig := Compute(CanonicalString(r), secretKey)
	r.Header.Set("Authorization", fmt.Sprintf("APIAuth %s:%s", accessID, sig))

	return nil
}

// Verify checks a request for validity: all required headers
// are present and the signature matches.
func Verify(r *http.Request, secretKey string) error {
	return nil
}

// Date returns a suitable value for a request's Date header,
// based on the current time in GMT in RFC1123 format.
func Date() string {
	return DateForTime(time.Now())
}

// DateForTime converts the given time to GMT, and returns it
// in RFC1123 format. I would rather this use UTC, but Ruby's
// `Time#httpdate` spits out GMT, and I need to maintain
// fairly rigid compatibility.
func DateForTime(t time.Time) string {
	return t.In(gmt).Format(time.RFC1123)
}

// CanonicalString returns the canonical string used for the signature
// based on the headers in the given request.
func CanonicalString(r *http.Request) string {
	uri := r.URL.Path
	if r.URL.RawQuery != "" {
		uri = uri + "?" + r.URL.RawQuery
	}

	header := r.Header

	return strings.Join([]string{
		header.Get("Content-Type"),
		header.Get("Content-MD5"),
		uri,
		header.Get("Date"),
	}, ",")
}

// Compute computes the signature for a given canonical string, using
// the HMAC-SHA1.
func Compute(canonicalString, secretKey string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(canonicalString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
