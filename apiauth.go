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
		log.Fatalf("Failed to load apiauth -  Can not load timezone Etc/GMT: %s. See https://golang.org/pkg/time/#LoadLocation", err.Error())
	}
	gmt = loc
}

// Sign computes the signature for the given HTTP request, and
// adds the resulting Authorization header value to it. If any
// of the prerequisite headers are absent, an error is returned.
func Sign(r *http.Request, accessID, secret string) error {
	if err := sufficientHeaders(r); err != nil {
		return err
	}

	preexisting := r.Header.Get("Authorization")
	if preexisting != "" {
		return fmt.Errorf("Authorization header already present")
	}

	sig := Compute(CanonicalString(r), secret)
	r.Header.Set("Authorization", fmt.Sprintf("APIAuth %s:%s", accessID, sig))

	return nil
}

// SignWithMethod computs the signature of the given HTTP request
// as in Sign except that the canonical string includes the HTTP
// request method.
func SignWithMethod(r *http.Request, accessID, secret string) error {
	if err := sufficientHeaders(r); err != nil {
		return err
	}

	preexisting := r.Header.Get("Authorization")
	if preexisting != "" {
		return fmt.Errorf("Authorization header already present")
	}

	sig := Compute(CanonicalStringWithMethod(r), secret)
	r.Header.Set("Authorization", fmt.Sprintf("APIAuth %s:%s", accessID, sig))

	return nil
}

// Verify checks a request for validity: all required headers
// are present and the signature matches.
func Verify(r *http.Request, secret string) error {
	if err := sufficientHeaders(r); err != nil {
		return err
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return fmt.Errorf("Authorization header not set")
	}

	_, sig, err := Parse(auth)
	if err != nil {
		return err
	}

	if VerifySignature(sig, CanonicalString(r), secret) || VerifySignature(sig, CanonicalStringWithMethod(r), secret) {
		return nil
	}

	return fmt.Errorf("Signature mismatch")
}

// VerifySignature computes the expected signature for a given
// canonical string and secret key pair, and returns true if the
// given signature matches.
func VerifySignature(sig, canonicalString, secret string) bool {
	expected := Compute(canonicalString, secret)
	return expected == sig
}

// Parse returns the access ID and signature present in the
// given string, presumably taken from a request's Authorization
// header. If the header does not match the expected `APIAuth access_id:signature`
// format, an error is returned.
func Parse(header string) (id, sig string, err error) {
	var tokens []string

	if !strings.HasPrefix(header, "APIAuth ") {
		goto malformed
	}

	tokens = strings.Split(header[8:], ":")
	if len(tokens) != 2 || tokens[0] == "" || tokens[1] == "" {
		goto malformed
	}

	return tokens[0], tokens[1], nil

malformed:
	return "", "", fmt.Errorf("Malformed header: %s", header)
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
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}

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

// CanonicalStringWithMethod returns a canonical string as in CanonicalString
// but also includes the request method
func CanonicalStringWithMethod(r *http.Request) string {
	return strings.Join([]string{
		strings.ToUpper(r.Method),
		CanonicalString(r),
	}, ",")
}

// Compute computes the signature for a given canonical string, using
// the HMAC-SHA1.
func Compute(canonicalString, secret string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(canonicalString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func sufficientHeaders(r *http.Request) error {
	date := r.Header.Get("Date")
	if date == "" {
		return fmt.Errorf("No Date header present")
	}

	if r.Body != nil {
		contentType := r.Header.Get("Content-Type")
		if contentType == "" {
			return fmt.Errorf("No Content-Type header present")
		}

		contentMD5 := r.Header.Get("Content-MD5")
		if contentMD5 == "" {
			return fmt.Errorf("No Content-MD5 header present")
		}
	}

	return nil
}
