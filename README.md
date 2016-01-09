# apiauth [![Build Status](https://travis-ci.org/pd/apiauth.png)](https://travis-ci.org/pd/apiauth) [![GoDoc](https://godoc.org/github.com/pd/apiauth?status.png)](https://godoc.org/github.com/pd/apiauth)

[ApiAuth][]-compatible package for signing and verifying HTTP requests in golang.

## IMPORTANT!: Security Update
In order to prevent a security vulnerability present in the reference version of
[ApiAuth][] we have added functions in order to sign and verify requests with a
canonical string that includes the HTTP method. We have added the fucntions
`SignWithMethod` and `CanonicalStringWithMethod`, and the `Verify` function has
been modified to accept requests where the request signature matches
`CanonicalString` OR `CanonicalStringWithMethod`. In the future the old versions
will be removed and canonical strings will only be considered a match if they 
include the request method. We recommend you start using the new way of siging
requests immediately.

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
* The `apiauth.Verify` function does *not* enforce a maximum time duration between the `Date` header
  in a request and the matching `Date` value computed by the server. Protection against replay attacks
  is the caller's responsibility. (**NB**: but maybe shouldn't be; I'm just being lazy right now, as
  it's already handled in the application I'm writing this for)
* The `apiauth.Verify` function does *not* validate the `Content-MD5` header: doing so would require
  reading the entire request body into memory at least once, which is undesirable in many use cases.
  Verification of the payload MD5 is the caller's responsibility.

[ApiAuth]: https://github.com/mgomes/api_auth
