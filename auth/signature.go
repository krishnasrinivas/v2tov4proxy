package auth

import "net/http"

const (
	signV2Algorithm = "AWS"
	signV4Algorithm = "AWS4-HMAC-SHA256"
	DateFormat      = "20060102T150405Z"
	yyyymmdd        = "20060102"
)

type Signer interface {
	Sign(method string, encodedResource string, encodedQuery string, headers http.Header) string
}
