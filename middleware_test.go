// Copyright 2020 Lauris BH. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.package proxy

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func testRequest(t *testing.T, req *http.Request, middleware func(h http.Handler) http.Handler) string {
	w := httptest.NewRecorder()

	r := chi.NewRouter()
	r.Use(middleware)

	realIP := ""
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		realIP = r.RemoteAddr
		w.Write([]byte("Hello World"))
	})
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Response status code")

	return realIP
}

func TestXRealIP(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Real-IP", "100.100.100.100")
	req.RemoteAddr = "127.0.0.1:111"

	realIP := testRequest(t, req, ForwardedHeaders())
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestXForwardForIP(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100")
	req.RemoteAddr = "127.0.0.1:111"

	realIP := testRequest(t, req, ForwardedHeaders())
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestXForwardForMultipleIP(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "100.100.100.100, 10.0.1.1, 10.1.1.3")
	req.RemoteAddr = "127.0.0.1:111"

	realIP := testRequest(t, req, ForwardedHeaders(NewForwardedHeadersOptions().WithForwardLimit(3)))
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestXForwardForMultipleIPWithLimit(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Forwarded-For", "10.0.1.1, 100.100.100.100, 10.1.1.3")
	req.RemoteAddr = "127.0.0.1:111"

	realIP := testRequest(t, req, ForwardedHeaders(NewForwardedHeadersOptions().WithForwardLimit(2)))
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestTrustedProxy(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Real-IP", "100.100.100.100")
	req.RemoteAddr = "127.0.1.2:111"

	realIP := testRequest(t, req, ForwardedHeaders(
		NewForwardedHeadersOptions().
			ClearTrustedProxies().AddTrustedProxy("127.0.1.2"),
	))
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestTrustedAllProxiesWildcard(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Real-IP", "100.100.100.100")
	req.RemoteAddr = "127.0.1.2:111"

	realIP := testRequest(t, req, ForwardedHeaders(
		NewForwardedHeadersOptions().
			ClearTrustedProxies().AddTrustedProxy("*"),
	))
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestTrustedAllProxies(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Real-IP", "100.100.100.100")
	req.RemoteAddr = "127.0.1.2:111"

	realIP := testRequest(t, req, ForwardedHeaders(
		NewForwardedHeadersOptions().
			ClearTrustedProxies().TrustAllProxies(),
	))
	assert.Equal(t, "100.100.100.100:0", realIP, "Request IP address")
}

func TestTrustedNetwork(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Real-IP", "100.100.100.100")
	req.RemoteAddr = "127.0.1.2:111"

	realIP := testRequest(t, req, ForwardedHeaders(
		NewForwardedHeadersOptions().
			ClearTrustedNetworks().AddTrustedNetwork("127.0.1.0/24"),
	))
	assert.Equal(t, "100.100.100.100:0", realIP)
}

func TestUntrustedProxy(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("X-Real-IP", "100.100.100.100")
	req.RemoteAddr = "127.0.1.2:111"

	realIP := testRequest(t, req, ForwardedHeaders())
	assert.Equal(t, "127.0.1.2:111", realIP, "Request IP address")
}
