package main

import (
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/vulcand/oxy/forward"
)

func (a v2auth) verifyAuth(r *http.Request) bool {
	expectedAuth := signV2(*r, a.accessKey, a.secretKey)
	gotAuth := r.Header.Get("Authorization")
	fmt.Println("got", gotAuth, "expected", expectedAuth)
	// return true
	return gotAuth == expectedAuth
}

// To forward the request to the address specified with -f
type v2auth struct {
	scheme    string
	host      string
	accessKey string
	secretKey string
	h         http.Handler
}

func (a v2auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// fmt.Println(r.URL.Path, r.URL.Query())
	// fmt.Println(r.URL.RawPath, r.URL.RawQuery)
	if !a.verifyAuth(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	r.Header.Del("Authorization")
	// Initial time.
	t := time.Now().UTC()

	// Set x-amz-date.
	r.Header.Set("X-Amz-Date", t.Format(iso8601DateFormat))
	r.Header.Del("Date")
	r.Header.Del("Connection")

	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.URL.Host = r.Host
	r.Header.Set("Authorization", signV4(*r, a.accessKey, a.secretKey, "us-east-1"))

	r.URL.Scheme = a.scheme
	r.URL.Host = a.host
	// body := r.Body
	// r.Body = struct {
	// 	io.Reader
	// 	io.Closer
	// }{
	// 	io.TeeReader(body, os.Stdout),
	// 	closer(func() error {
	// 		return body.Close()
	// 	}),
	// }
	a.h.ServeHTTP(w, r)
}

// To typecast a func to io.Closer
type closer func() error

func (c closer) Close() error {
	return c()
}

type rewrite struct{}

func (r rewrite) Rewrite(req *http.Request) {

}

func main() {
	listenAddr := flag.String("l", ":8000", "listen address")
	fwdAddr := flag.String("f", "localhost:9000", "forward address")
	accessKey := flag.String("access", "", "access key")
	secretKey := flag.String("secret", "", "secret key")
	cert := flag.String("cert", "", "certficate for https")
	key := flag.String("key", "", "key for https")
	flag.Parse()

	if *accessKey == "" || *secretKey == "" {
		fmt.Println("access/secret key should be specified")
		return
	}
	fwd, _ := forward.New(forward.PassHostHeader(true), forward.Rewriter(rewrite{}))
	server := &http.Server{
		Addr:    *listenAddr,
		Handler: v2auth{"http", *fwdAddr, *accessKey, *secretKey, fwd},
	}

	if *cert != "" && *key != "" {
		fmt.Println(server.ListenAndServeTLS(*cert, *key))
	} else {
		fmt.Println(server.ListenAndServe())
	}
}
