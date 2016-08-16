package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/url"
	"strings"
)

type ByQueryKey []string

func (q ByQueryKey) Len() int      { return len(q) }
func (q ByQueryKey) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q ByQueryKey) Less(i, j int) bool {
	keyI := strings.SplitN(q[i], "=", 2)[0]
	keyJ := strings.SplitN(q[j], "=", 2)[0]
	return keyI < keyJ
}

// sum256 calculate sha256 sum for an input byte array.
func sum256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// sumHMAC calculate hmac between two input byte array.
func sumHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func sortQuery(encodedQuery string) string {
	m, _ := url.ParseQuery(encodedQuery)
	return m.Encode()
	// queries := strings.Split(encodedQuery, "&")
	// var newQueries []string
	// for _, query := range queries {
	// 	if query != "" && !strings.Contains(query, "=") {
	// 		query = query + "="
	// 	}
	// 	newQueries = append(newQueries, query)
	// }
	// sort.Sort(ByQueryKey(newQueries))
	// return strings.Join(newQueries, "&")
}
