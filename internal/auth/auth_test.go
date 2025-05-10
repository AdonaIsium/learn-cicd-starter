package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApiKey myvalidapikey")

	_, err := GetAPIKey(req.Header)
	if err != nil {
		t.Errorf("error getting API key: %v", err)
	}
}

func TestGetAPIKey_Malformed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApKey myvalidapikey")

	_, err := GetAPIKey(req.Header)
	if err != nil {
		if err == ErrMalformedAuthHeader {
			return
		}
		t.Errorf("error getting API key: %v", err)
	}
}

func TestGetAPIKey_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := GetAPIKey(req.Header)
	if err != nil {
		if err == ErrNoAuthHeaderIncluded {
			return
		}
		t.Errorf("error getting API key: %v", err)
	}
}
