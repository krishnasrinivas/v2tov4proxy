package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/krishnasrinivas/v2tov4proxy/auth"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/utils"
)

// Proxy from a V2 ingress to V4 egress.
type proxy struct {
	scheme  string       // http or https of the Minio server
	host    string       // host:port of the Minio server
	ingress auth.Signer  // signer at the ingress (V2)
	egress  auth.Signer  // signer at the egress (v4)
	h       http.Handler // forwarding handler
}

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Authorization"), auth.SignV4Algorithm) {
		// If the signature is V4 then pass through the request as is
		// as it will be authenticated by the Minio server.
		p.h.ServeHTTP(w, r)
		return
	}

	// url.RawPath will be valid if path has any encoded characters, if not it will
	// be empty - in which case we need to consider url.Path (bug in net/http?)
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

	if gotAuth != expectedAuth {
		fmt.Printf("Error: got: %s, expected:%s\n", gotAuth, expectedAuth)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	dateStr := time.Now().UTC().Format(auth.DateFormat)
	r.Header.Set("X-Amz-Date", dateStr)                      // Mandatory for V4 signature.
	r.Header.Set("Host", r.Host)                             // Host header at the ingress will be availabe as r.Host
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") // We don't compute SHA256 for the data.

	// In case _ or - ro ~ were encoded, decode it - to be V4 compatible.
	encodedResource = canonicalEncoding(encodedResource)
	encodedQuery = canonicalEncoding(encodedQuery)
	r.URL.RawPath = encodedResource
	r.URL.RawQuery = encodedQuery
	r.URL.Path = canonicalEncoding(r.URL.Path)

	// for encodedQuery, "/" should be encoded. (mc currently does not encode "/")
	encodedQuery = strings.Replace(encodedQuery, "/", "%2F", -1)
	r.Header.Set("Authorization", p.egress.Sign(r.Method, encodedResource, encodedQuery, r.Header))

	// Forward the request to Minio server.
	r.URL.Scheme = p.scheme
	r.URL.Host = p.host
	p.h.ServeHTTP(w, r)
}

// Sign-V4 spec mandates - _ ~ not to be encoded.
func canonicalEncoding(str string) string {
	str = strings.Replace(str, "%2D", "-", -1)
	str = strings.Replace(str, "%5F", "_", -1)
	str = strings.Replace(str, "%7E", "~", -1)
	return str
}

// We have a no-op rewriter so that the forwarder does not add it's own headers.
type norewrite struct{}

func (r norewrite) Rewrite(req *http.Request) {}

func main() {
	// Local listening address for ingress data.
	listenAddr := flag.String("l", ":8000", "listen address")
	// Forwarding address.
	fwdAddr := flag.String("f", "http://localhost:9000", "forward address")

	// Credentials.
	accessKey := flag.String("access", "", "access key")
	secretKey := flag.String("secret", "", "secret key")

	// If cert and key is specified we enable https on listening server.
	cert := flag.String("cert", "", "certficate for https")
	key := flag.String("key", "", "key for https")
	flag.Parse()

	host := *fwdAddr
	scheme := "http"
	u, err := url.Parse(*fwdAddr)
	if err == nil {
		host = u.Host
		if u.Scheme != "" {
			scheme = u.Scheme
		}
	}

	if *accessKey == "" || *secretKey == "" {
		fmt.Println("access/secret key should be specified")
		return
	}

	// Forwarding http.Handler
	fwd, _ := forward.New(forward.PassHostHeader(true), forward.Rewriter(norewrite{}), forward.Logger(utils.NewFileLogger(os.Stdout, utils.INFO)))

	// HTTP server.
	server := &http.Server{
		Addr: *listenAddr,
		Handler: proxy{
			scheme,
			host,
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
