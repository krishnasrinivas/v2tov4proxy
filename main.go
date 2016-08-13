package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/krishnasrinivas/v2tov4proxy/auth"
	"github.com/vulcand/oxy/forward"
)

type proxy struct {
	scheme  string
	host    string
	ingress auth.Signer
	egress  auth.Signer
	h       http.Handler
}

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	encodedResource := r.URL.RawPath
	encodedQuery := r.URL.RawQuery
	if encodedResource == "" {
		splits := strings.Split(r.URL.Path, "?")
		if len(splits) > 0 {
			encodedResource = splits[0]
		}
	}

	expectedAuth := p.ingress.Sign(r.Method, encodedResource, encodedQuery, r.Header)
	gotAuth := r.Header.Get("Authorization")
	fmt.Println("got", gotAuth, "expected", expectedAuth)

	if gotAuth != expectedAuth {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	r.Header.Del("Authorization")

	r.Header.Set("X-Amz-Date", time.Now().UTC().Format(auth.DateFormat))

	r.Header.Del("Date")
	r.Header.Del("Connection")

	r.Header.Set("Host", r.Host)
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.Header.Set("Authorization", p.egress.Sign(r.Method, encodedResource, strings.Replace(encodedQuery, "/", "%2F", -1), r.Header))

	r.URL.Scheme = p.scheme
	r.URL.Host = p.host
	p.h.ServeHTTP(w, r)
}

type norewrite struct{}

func (r norewrite) Rewrite(req *http.Request) {}

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
	fwd, _ := forward.New(forward.PassHostHeader(true), forward.Rewriter(norewrite{}))
	server := &http.Server{
		Addr: *listenAddr,
		Handler: proxy{
			"http",
			*fwdAddr,
			auth.CredentialsV2{*accessKey, *secretKey, "us-east-1"},
			auth.CredentialsV4{*accessKey, *secretKey, "us-east-1"},
			fwd,
		},
	}

	if *cert != "" && *key != "" {
		fmt.Println(server.ListenAndServeTLS(*cert, *key))
	} else {
		fmt.Println(server.ListenAndServe())
	}
}
