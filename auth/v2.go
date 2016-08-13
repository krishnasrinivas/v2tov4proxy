package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

var resourceList = []string{
	"acl",
	"lifecycle",
	"location",
	"logging",
	"notification",
	"partNumber",
	"policy",
	"requestPayment",
	"torrent",
	"uploadId",
	"uploads",
	"versionId",
	"versioning",
	"versions",
	"website",
}

type CredentialsV2 struct {
	AccessKey string
	SecretKey string
	Region    string
}

func (c CredentialsV2) Sign(method string, encodedResource string, encodedQuery string, headers http.Header) string {
	canonicalHeaaders := canonicalizedAmzHeadersV2(headers)
	if len(canonicalHeaaders) > 0 {
		canonicalHeaaders += "\n"
	}

	stringToSign := strings.Join([]string{
		method,
		headers.Get("Content-MD5"),
		headers.Get("Content-Type"),
		headers.Get("Date"),
		canonicalHeaaders,
	}, "\n") + canonicalizedResourceV2(encodedResource, encodedQuery)
	fmt.Println(stringToSign)
	hm := hmac.New(sha1.New, []byte(c.SecretKey))
	hm.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(hm.Sum(nil))
	return fmt.Sprintf("%s %s:%s", signV2Algorithm, c.AccessKey, signature)
}

func canonicalizedAmzHeadersV2(headers http.Header) string {
	var keys []string
	keyval := make(map[string]string)
	for key := range headers {
		lkey := strings.ToLower(key)
		if !strings.HasPrefix(lkey, "x-amz-") {
			continue
		}
		keys = append(keys, lkey)
		keyval[lkey] = strings.Join(headers[key], ",")
	}
	sort.Strings(keys)
	var canonicalHeaders []string
	for _, key := range keys {
		canonicalHeaders = append(canonicalHeaders, key+":"+keyval[key])
	}
	return strings.Join(canonicalHeaders, "\n")
}

func canonicalizedResourceV2(encodedPath string, encodedQuery string) string {
	queries := strings.Split(encodedQuery, "&")
	keyval := make(map[string]string)
	for _, query := range queries {
		key := query
		val := ""
		index := strings.Index(query, "=")
		if index != -1 {
			key = query[:index]
			val = query[index:]
		}
		keyval[key] = val
	}
	var canonicalQueries []string
	for _, key := range resourceList {
		val, ok := keyval[key]
		if !ok {
			continue
		}
		if val == "" {
			canonicalQueries = append(canonicalQueries, key)
			continue
		}
		canonicalQueries = append(canonicalQueries, key+"="+val)
	}
	if len(canonicalQueries) == 0 {
		return encodedPath
	}
	// the queries will be already sorted as resourceList is sorted.
	return encodedPath + "?" + strings.Join(canonicalQueries, "&")
}
