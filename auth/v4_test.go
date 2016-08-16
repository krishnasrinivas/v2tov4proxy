package auth

import (
	"net/http"
	"testing"
)

type keyval struct {
	key string
	val string
}

type argument struct {
	method   string
	resource string
	query    string
	headers  http.Header
}

func getHeader(entries []keyval) http.Header {
	header := make(http.Header)
	for _, entry := range entries {
		header.Add(entry.key, entry.val)
	}
	return header
}

func TestSignv4(t *testing.T) {
	c := CredentialsV4{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1"}

	testCases := []struct {
		arg   argument
		authz string
	}{
		{
			// get-vanilla
			argument{
				"GET",
				"/",
				"",
				getHeader([]keyval{
					{"Host", "example.amazonaws.com"},
					{"X-Amz-Date", "20150830T123600Z"},
				}),
			},
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			// get-vanilla-empty-query-key
			argument{
				"GET",
				"/",
				"Param1=value1",
				getHeader([]keyval{
					{"Host", "example.amazonaws.com"},
					{"X-Amz-Date", "20150830T123600Z"},
				}),
			},
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb",
		},
		{
			// get-vanilla-query-order-key-case
			argument{
				"GET",
				"/",
				"Param2=value2&Param1=value1",
				getHeader([]keyval{
					{"Host", "example.amazonaws.com"},
					{"X-Amz-Date", "20150830T123600Z"},
				}),
			},
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
		},
		{
			// get-vanilla-query-unreserved
			argument{
				"GET",
				"/",
				"-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
				getHeader([]keyval{
					{"Host", "example.amazonaws.com"},
					{"X-Amz-Date", "20150830T123600Z"},
				}),
			},
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197",
		},
	}
	for _, test := range testCases {
		expected := test.authz
		got := c.Sign(test.arg.method, test.arg.resource, test.arg.query, test.arg.headers)
		if expected == got {
			continue
		}
		t.Errorf("got: %s\n expected: %s\n", got, expected)
	}
}
