// Package policy implements a deliberately narrow public API credential gate.
// It checks syntax only. The private CLIProxyAPI Core remains authoritative.
package policy

import (
	"net/http"
	"regexp"
	"strings"
)

var bearerCPA = regexp.MustCompile(`^(?i:Bearer) cpa_[A-Za-z0-9_-]{43}$`)

// disallowedHeaders lists alternative credential mechanisms which could be
// interpreted differently by downstream middleware or native CPA auth.
var disallowedHeaders = map[string]bool{
	"x-api-key":          true,
	"api-key":            true,
	"x-goog-api-key":     true,
	"x-openai-api-key":   true,
	"proxy-authorization": true,
}

var disallowedQuery = map[string]bool{
	"api_key":       true,
	"apikey":        true,
	"api-key":       true,
	"key":           true,
	"authorization": true,
	"access_token":  true,
}

// Accept rejects missing, malformed, duplicated, or ambiguous credentials.
// Never return or log the credential value. Even an accepted syntactic key
// must be authenticated independently by private Core.
func Accept(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}

	for name := range r.URL.Query() {
		if disallowedQuery[strings.ToLower(name)] {
			return false
		}
	}

	var authorization []string
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if disallowedHeaders[lower] {
			return false
		}
		if lower == "authorization" {
			authorization = append(authorization, values...)
		}
	}
	return len(authorization) == 1 && bearerCPA.MatchString(authorization[0])
}
