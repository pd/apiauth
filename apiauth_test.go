package apiauth

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCanonicalString(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://example.com", nil)
	require.Equal(t, ",,/,", CanonicalString(req))

	req.URL.Path = "/"
	require.Equal(t, ",,/,", CanonicalString(req))

	req.URL.Path = "/some/path"
	require.Equal(t, ",,/some/path,", CanonicalString(req))

	req.URL.RawQuery = "x=1&b=2"
	require.Equal(t, ",,/some/path?x=1&b=2,", CanonicalString(req))

	req.Header.Add("Content-Type", "text/plain")
	req.Header.Add("Content-MD5", "WnNni3tnQAUFZDSkgFRwfQ==")
	req.Header.Add("Date", "Thu, 19 Mar 2015 19:24:24 GMT")

	want := "text/plain,WnNni3tnQAUFZDSkgFRwfQ==,/some/path?x=1&b=2,Thu, 19 Mar 2015 19:24:24 GMT"
	require.Equal(t, want, CanonicalString(req))
}

func TestCompute(t *testing.T) {
	canonicalString := "text/plain,WnNni3tnQAUFZDSkgFRwfQ==,/a?b=c,Thu, 19 Mar 2015 19:34:03 GMT"
	want := "cMgmUVsq4IiT7baALMM1euHnpCo="
	require.Equal(t, want, Compute(canonicalString, "secret"))
}

func TestDateForTime(t *testing.T) {
	chi, err := time.LoadLocation("America/Chicago")
	require.NoError(t, err)

	tm := time.Date(2015, time.March, 19, 14, 34, 03, 0, chi)
	require.Equal(t, "Thu, 19 Mar 2015 19:34:03 GMT", DateForTime(tm))
}

func TestDate(t *testing.T) {
	require.Equal(t, DateForTime(time.Now()), Date())
}

func TestSign(t *testing.T) {
	get, _ := http.NewRequest("GET", "http://example.com", nil)
	get.Header.Set("Date", "Fri, 20 Mar 2015 19:37:40 GMT")

	require.NoError(t, Sign(get, "me", "secret"))
	require.Equal(t, "APIAuth me:N7N1BXAWv6+RXos4vSAAd7D0XJY=", get.Header.Get("Authorization"))

	post, _ := http.NewRequest("POST", "http://example.com", nil)
	post.Header.Set("Date", "Fri, 20 Mar 2015 19:37:40 GMT")
	post.Header.Set("Content-Type", "text/plain")
	post.Header.Set("Content-MD5", "WnNni3tnQAUFZDSkgFRwfQ==")

	require.NoError(t, Sign(post, "me", "secret"))
	require.Equal(t, "APIAuth me:/Z/MqEW+v23Cm3w3Ra2mMGH9KFw=", post.Header.Get("Authorization"))
}

func TestSign_AuthorizationHeaderPresent(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Date", Date())
	req.Header.Set("Authorization", "anything")

	err := Sign(req, "me", "key")
	require.Error(t, err)
}

func TestSign_GETNoDate(t *testing.T) {
	secretKey := "secret"

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	require.Error(t, Sign(req, "me", secretKey))
	require.Equal(t, "", req.Header.Get("Authorization"))

	req.Header.Set("date", Date())
	require.NoError(t, Sign(req, "me", secretKey))
}

func TestSign_WithBody(t *testing.T) {
	body := []byte(`post body`)
	req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader(body))

	req.Header.Set("Date", Date())
	require.Error(t, Sign(req, "me", "secret"))

	req.Header.Set("Content-Type", "text/plain")
	require.Error(t, Sign(req, "me", "secret"))

	req.Header.Set("Content-MD5", base64md5(body))
	require.NoError(t, Sign(req, "me", "secret"))
}

func base64md5(bytes []byte) string {
	sum := md5.Sum(bytes)
	return base64.StdEncoding.EncodeToString(sum[:])
}
