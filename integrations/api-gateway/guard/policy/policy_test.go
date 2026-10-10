package policy

import (
 "net/http"
 "net/url"
 "strings"
 "testing"
)

func makeRequest(auth string) *http.Request {
 u, _ := url.Parse("http://gateway.test/v1/chat/completions")
 r := &http.Request{Method: "POST", URL: u, Header: make(http.Header)}
 if auth != "" { r.Header.Set("Authorization", auth) }
 return r
}

func TestAccept(t *testing.T) {
 secret := "cpa_" + strings.Repeat("a", 43)
 cases := []struct { name string; modify func(*http.Request); want bool }{
  {"valid", nil, true},
  {"lowercase_scheme", func(r *http.Request) { r.Header.Set("Authorization", "bearer " + secret) }, true},
  {"missing", func(r *http.Request) { r.Header.Del("Authorization") }, false},
  {"native", func(r *http.Request) { r.Header.Set("Authorization", "Bearer sk_" + strings.Repeat("a", 43)) }, false},
  {"preview", func(r *http.Request) { r.Header.Set("Authorization", "Bearer cpa_abc...") }, false},
  {"short", func(r *http.Request) { r.Header.Set("Authorization", "Bearer cpa_" + strings.Repeat("a", 42)) }, false},
  {"long", func(r *http.Request) { r.Header.Set("Authorization", "Bearer cpa_" + strings.Repeat("a", 44)) }, false},
  {"spaces", func(r *http.Request) { r.Header.Set("Authorization", "Bearer  " + secret) }, false},
  {"trailing_space", func(r *http.Request) { r.Header.Set("Authorization", "Bearer " + secret + " ") }, false},
  {"duplicate", func(r *http.Request) { r.Header.Add("Authorization", "Bearer " + secret) }, false},
  {"case_duplicate", func(r *http.Request) { r.Header["authorization"] = []string{"Bearer " + secret} }, false},
  {"combined", func(r *http.Request) { r.Header.Set("Authorization", "Bearer " + secret + ", Bearer " + secret) }, false},
  {"x_api_key", func(r *http.Request) { r.Header.Set("X-Api-Key", "native") }, false},
  {"api_key", func(r *http.Request) { r.Header.Set("Api-Key", "native") }, false},
  {"google", func(r *http.Request) { r.Header.Set("X-Goog-Api-Key", "native") }, false},
  {"openai", func(r *http.Request) { r.Header.Set("X-Openai-Api-Key", "native") }, false},
  {"proxy", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Basic x") }, false},
  {"query_key", func(r *http.Request) { r.URL.RawQuery = "key=x" }, false},
  {"query_api_key", func(r *http.Request) { r.URL.RawQuery = "api_key=x" }, false},
  {"query_case", func(r *http.Request) { r.URL.RawQuery = "API_Key=x" }, false},
  {"query_encoded", func(r *http.Request) { r.URL.RawQuery = "%61pi_key=x" }, false},
  {"query_token", func(r *http.Request) { r.URL.RawQuery = "access_token=x" }, false},
  {"safe_query", func(r *http.Request) { r.URL.RawQuery = "model=gpt-6-luna&audit=1" }, true},
 }
 for _, tc := range cases { t.Run(tc.name, func(t *testing.T) {
  r := makeRequest("Bearer "+secret)
  if tc.modify != nil { tc.modify(r) }
  if got := Accept(r); got != tc.want { t.Fatalf("got %t, want %t",got,tc.want) }
 }) }
}

func TestNil(t *testing.T) {
 if Accept(nil) || Accept(&http.Request{}) { t.Fatal("nil accepted") }
}
