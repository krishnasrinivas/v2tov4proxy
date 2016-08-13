package auth

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
	"time"
)

var ignoredHeaders = map[string]bool{
	"authorization":  true,
	"content-type":   true,
	"content-length": true,
	"user-agent":     true,
}

type CredentialsV4 struct {
	AccessKey string
	SecretKey string
	Region    string
}

func (c CredentialsV4) Sign(method string, encodedResource string, encodedQuery string, headers http.Header) (authHeader string) {
	dateStr := headers.Get("X-Amz-Date")
	date, _ := time.Parse(DateFormat, dateStr)
	canonicalReq := getCanonicalRequest(method, encodedResource, encodedQuery, headers)
	fmt.Println(canonicalReq)
	stringToSign := strings.Join([]string{
		signV4Algorithm,
		date.Format(DateFormat),
		getScope(c.Region, date),
		hex.EncodeToString(sum256([]byte(canonicalReq))),
	}, "\n")
	fmt.Println(stringToSign)
	signingKey := getSigningKey(c.SecretKey, c.Region, date)

	credential := getCredential(c.AccessKey, c.Region, date)

	signedHeaders := getSignedHeaders(headers)

	signature := getSignature(signingKey, stringToSign)

	authHeader = strings.Join([]string{
		signV4Algorithm + " Credential=" + credential,
		" SignedHeaders=" + signedHeaders,
		" Signature=" + signature,
	}, ",")

	return authHeader
}

func getCanonicalRequest(method string, encodedResource string, encodedQuery string, headers http.Header) string {
	return strings.Join([]string{
		method,
		encodedResource,
		sortQuery(encodedQuery),
		getCanonicalHeaders(headers),
		getSignedHeaders(headers),
		getHashedPayload(headers),
	}, "\n")
}

func getCanonicalHeaders(headers http.Header) string {
	keys := signedHeaders(headers)
	var canonicalHeaders []string
	for _, key := range keys {
		canonicalHeaders = append(canonicalHeaders,
			key+":"+strings.Join(headers[textproto.CanonicalMIMEHeaderKey(key)], ","),
		)
	}
	return strings.Join(canonicalHeaders, "\n") + "\n"
}

func signedHeaders(headers http.Header) []string {
	var keys []string
	for key := range headers {
		lkey := strings.ToLower(key)
		if ignoredHeaders[lkey] {
			continue
		}
		keys = append(keys, lkey)
	}
	sort.Strings(keys)
	return keys
}

func getSignedHeaders(headers http.Header) string {
	return strings.Join(signedHeaders(headers), ";")
}

func getHashedPayload(headers http.Header) string {
	hashedPayload := headers.Get("X-Amz-Content-Sha256")
	if hashedPayload == "" {
		hashedPayload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	return hashedPayload
}

func getScope(region string, date time.Time) string {
	scope := strings.Join([]string{
		date.Format(yyyymmdd),
		region,
		"s3",
		"aws4_request",
	}, "/")
	return scope
}

func getCredential(accessKey, region string, date time.Time) string {
	return accessKey + "/" + getScope(region, date)
}

func getSigningKey(secret, region string, date time.Time) []byte {
	dateKey := sumHMAC([]byte("AWS4"+secret), []byte(date.Format(yyyymmdd)))
	dateRegionKey := sumHMAC(dateKey, []byte(region))
	dateRegionServiceKey := sumHMAC(dateRegionKey, []byte("s3"))
	signingKey := sumHMAC(dateRegionServiceKey, []byte("aws4_request"))
	return signingKey
}

func getSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))
}
