package ssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

func testACMEConfig(t *testing.T, s *httptest.Server) *lego.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := lego.NewConfig(&MyUser{key: key})
	config.CADirURL = s.URL + "/directory"
	config.HTTPClient = s.Client()
	return config
}

func writeTestACMEDirectory(w http.ResponseWriter, r *http.Request) {
	base := "https://" + r.Host
	_ = json.NewEncoder(w).Encode(map[string]string{
		"newNonce": base + "/new-nonce", "newAccount": base + "/new-account", "newOrder": base + "/new-order",
	})
}

func TestACMEDirectoryRetries(t *testing.T) {
	for _, tt := range []struct {
		name         string
		status       int
		recoverAt    int32
		retries      int
		wantAttempts int32
		wantErr      string
	}{
		{"recovers", http.StatusServiceUnavailable, 2, 5, 2, ""},
		{"last attempt recovers", http.StatusGatewayTimeout, 6, 5, 6, ""},
		{"exhausted", http.StatusBadGateway, 0, 5, 6, "HTTP 502"},
		{"disabled", http.StatusServiceUnavailable, 0, 0, 1, "HTTP 503"},
		{"denied", http.StatusForbidden, 0, 5, 1, "HTTP 403"},
		{"rate limited", http.StatusTooManyRequests, 0, 5, 1, "HTTP 429"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/directory" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if attempts.Add(1) == tt.recoverAt {
					writeTestACMEDirectory(w, r)
					return
				}
				http.Error(w, "CA response is not logged", tt.status)
			}))
			defer s.Close()
			var delays []time.Duration
			_, err := openACMEClient(t.Context(), nil, testACMEConfig(t, s), time.Second, tt.retries, func(_ context.Context, delay time.Duration) error {
				delays = append(delays, delay)
				return nil
			})
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr) || strings.Contains(err.Error(), "CA response is not logged")) {
				t.Fatalf("err=%v, want %q", err, tt.wantErr)
			}
			if attempts.Load() != tt.wantAttempts || len(delays) != int(tt.wantAttempts)-1 {
				t.Fatalf("attempts=%d, delays=%v, want %d attempts", attempts.Load(), delays, tt.wantAttempts)
			}
			for i, delay := range delays {
				want := time.Second << i
				if delay < want || delay >= want+500*time.Millisecond {
					t.Errorf("retry delay %d = %v, want %v to %v", i, delay, want, want+500*time.Millisecond)
				}
			}
		})
	}
}

func TestACMEDirectoryTimeout(t *testing.T) {
	for _, duringBody := range []bool{false, true} {
		name := "response headers"
		if duringBody {
			name = "response body"
		}
		t.Run(name, func(t *testing.T) {
			var attempts atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 2 {
					writeTestACMEDirectory(w, r)
					return
				}
				if duringBody {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-time.After(3 * time.Second):
					t.Error("timed-out directory request was not canceled")
				}
			}))
			defer s.Close()
			_, err := openACMEClient(t.Context(), nil, testACMEConfig(t, s), 150*time.Millisecond, 1, func(_ context.Context, _ time.Duration) error { return nil })
			if err != nil || attempts.Load() != 2 {
				t.Fatalf("attempts=%d, err=%v", attempts.Load(), err)
			}
		})
	}
}

func TestACMEDirectoryUsesOwnTimeoutAndDoesNotRetryRegistration(t *testing.T) {
	var registrations atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			time.Sleep(50 * time.Millisecond)
			writeTestACMEDirectory(w, r)
		case "/new-nonce":
			w.Header().Set("Replay-Nonce", "test-nonce")
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			registrations.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:serverInternal","detail":"try again later"}`))
		}
	}))
	defer s.Close()
	config := testACMEConfig(t, s)
	base := config.HTTPClient.Transport.(*http.Transport)
	base.ResponseHeaderTimeout = 15 * time.Millisecond
	normalTimeout := config.HTTPClient.Timeout
	client, err := openACMEClient(t.Context(), nil, config, 2*time.Second, 5, func(context.Context, time.Duration) error {
		t.Error("unexpected directory retry")
		return errors.New("unexpected retry")
	})
	if err != nil {
		t.Fatalf("directory must be allowed to exceed the original response header timeout: %v", err)
	}
	if base.ResponseHeaderTimeout != 15*time.Millisecond || config.HTTPClient.Timeout != normalTimeout {
		t.Fatal("shared input configuration changed")
	}
	_, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	var problem *acme.ProblemDetails
	if !errors.As(err, &problem) || problem.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("want original account registration error, got %v", err)
	}
	if registrations.Load() != 1 {
		t.Fatalf("got %d registration requests, want 1", registrations.Load())
	}
}

func TestACMEDirectoryPermanentErrorsAndRetryAfter(t *testing.T) {
	for _, tt := range []struct {
		name, after, wantErr string
		wantDelay            time.Duration
	}{
		{"retry after", "20", "HTTP 503", 20 * time.Second},
		{"retry after too long", "31", "CA 要求稍后再试", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", tt.after)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer s.Close()
			var delay time.Duration
			_, err := openACMEClient(t.Context(), nil, testACMEConfig(t, s), time.Second, 1, func(_ context.Context, d time.Duration) error {
				delay = d
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || delay != tt.wantDelay {
				t.Fatalf("err=%v, delay=%v; want %q, %v", err, delay, tt.wantErr, tt.wantDelay)
			}
		})
	}
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	config := testACMEConfig(t, s)
	config.HTTPClient = &http.Client{Transport: &http.Transport{}}
	noRetry := func(context.Context, time.Duration) error {
		t.Error("unexpected retry")
		return errors.New("unexpected retry")
	}
	if _, err := openACMEClient(t.Context(), nil, config, time.Second, 5, noRetry); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("unexpected certificate error: %v", err)
	}
	config.CADirURL = "http://example.invalid/directory"
	if _, err := openACMEClient(t.Context(), nil, config, time.Second, 5, noRetry); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("unexpected URL error: %v", err)
	}
}

func TestACMEDirectoryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	defer s.Close()
	_, err := openACMEClient(ctx, nil, testACMEConfig(t, s), 10*time.Second, 5, func(context.Context, time.Duration) error {
		t.Error("unexpected retry after cancellation")
		return errors.New("unexpected retry")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
}
