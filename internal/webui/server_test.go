package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MinottiAlessandro/WhereDNS/internal/dnsengine"
)

func TestCurriculumAPIAndSecurityHeaders(t *testing.T) {
	cache, _ := dnsengine.NewCache("")
	handler := New(dnsengine.New(cache)).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/attacks", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "cache-poisoning") {
		t.Fatal("attack catalog missing from API")
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing Content-Security-Policy")
	}
}

func TestLabAPI(t *testing.T) {
	cache, _ := dnsengine.NewCache("")
	handler := New(dnsengine.New(cache)).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/labs/rebinding", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Public origin") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
