package panel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubscriptionWantsHTML(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		ua     string
		query  string
		want   bool
	}{
		{"browser", "text/html,application/xhtml+xml", "Mozilla/5.0 Chrome/120", "", true},
		{"vpn client", "*/*", "HiddifyNext/1.0", "", false},
		{"okhttp", "*/*", "okhttp/4.9.0", "", false},
		{"explicit html", "*/*", "", "html=1", true},
		{"explicit raw", "text/html", "Mozilla/5.0", "format=raw", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/sub/test?"+tc.query, nil)
			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}
			if tc.ua != "" {
				r.Header.Set("User-Agent", tc.ua)
			}
			if got := subscriptionWantsHTML(r); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestSubscriptionUsesBase64(t *testing.T) {
	for _, tc := range []struct {
		format           string
		configured, want bool
	}{
		{"raw", true, false},
		{"BASE64", false, true},
		{"sub", true, true},
		{"", false, false},
	} {
		if got := subscriptionUsesBase64(tc.format, tc.configured); got != tc.want {
			t.Errorf("format %q, configured %t: got %t, want %t", tc.format, tc.configured, got, tc.want)
		}
	}
}
