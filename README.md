# apiauth [![Build Status](https://travis-ci.org/pd/apiauth.png)](https://travis-ci.org/pd/apiauth) [![GoDoc](https://godoc.org/github.com/pd/apiauth?status.png)](https://godoc.org/github.com/pd/apiauth)

[ApiAuth][]-compatible package for signing and verifying HTTP requests in golang.

## Usage

Signing a request:

~~~go
import "github.com/pd/apiauth"

req, _ := http.NewRequest("GET", "http://example.com", nil)

// The `Date` header _must_ be present.
// If the request body is set, `Content-Type` and `Content-MD5` must
// also be present.
req.Header.Set("Date", apiauth.Date())

err := apiauth.Sign(req, "access_id", "secret_key")
~~~

Verifying a request:

~~~go
err := apiauth.Verify(req, "secret_key")
if err != nil {
  // Failed.
}
~~~

Functions are exposed for the lower-level operations, as well, in case you need more granular control:

~~~go
// Given a request, returns the `<Content-Type>,<MD5>,<URI>,<Date>` string used for the HMAC.
str := apiauth.CanonicalString(req)

// Given a canonical string and secret key, computes the signature using HMAC-SHA1:
signature := apiauth.Compute(str, "secret_key")

// A helper for generating a RFC1123-formatted date using the current time:
apiauth.Date()

// Or a given time:
t := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
apiauth.DateForTime(t)
~~~

## Caveats

This implementation is intentionally somewhat less "friendly" than mgomes' [Ruby implementation][ApiAuth]:

* Only the `Authorization` header is set for you by `apiauth.Sign`; setting the `Date`, `Content-Type`
  and `Content-MD5` headers is the caller's responsibility.
* The `apiauth.Verify` function does *not* validate the `Content-MD5` header: doing so would require
  reading the entire request body into memory at least once, which is undesirable in many use cases.
  Verification of the payload MD5 is the caller's responsibility.

[ApiAuth]: https://github.com/mgomes/api_auth
