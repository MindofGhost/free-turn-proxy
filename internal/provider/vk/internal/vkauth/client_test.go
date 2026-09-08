package vkauth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/pion/stun/v3"
)

// newTestClient builds a Client with a zero-interval throttle and the supplied
// fake token-chain fetcher.
func newTestClient(t *testing.T, fake tokenChainFn, opts ...func(*Client)) *Client { //nolint:unparam
	t.Helper()
	c := New(Config{
		StreamsPerCache: 10,
		Credentials:     []VKCredentials{{ClientID: "a"}, {ClientID: "b"}, {ClientID: "c"}},
	})
	c.tokenChain = fake
	c.minFetchIntervalFn = func() time.Duration { return 0 }
	for _, o := range opts {
		o(c)
	}
	return c
}

func TestIsAuthError(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"401 Unauthorized":                     true,
		"alloc failed: 401":                    true,
		"stale nonce":                          true,
		"invalid credential":                   true,
		"authentication required":              true,
		"connection refused":                   false,
		"dial tcp 10.0.0.1:48612: i/o timeout": false,
		"":                                     false,
	}
	for msg, want := range cases {
		got := IsAuthError(errors.New(msg))
		if got != want {
			t.Errorf("IsAuthError(%q) = %v, want %v", msg, got, want)
		}
	}
	if IsAuthError(nil) {
		t.Error("IsAuthError(nil) = true; want false")
	}
}

func TestIsAuthErrorTurnCode(t *testing.T) {
	t.Parallel()

	codes := map[stun.ErrorCode]bool{
		stun.CodeAllocQuotaReached:    true,
		stun.CodeUnauthorized:         true,
		stun.CodeStaleNonce:           true,
		stun.CodeWrongCredentials:     true,
		stun.CodeInsufficientCapacity: false,
		stun.CodeForbidden:            false,
	}
	for code, want := range codes {
		err := fmt.Errorf("TURN allocate: %w", &stun.TurnError{
			StunMessageType: stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse),
			ErrorCodeAttr:   stun.ErrorCodeAttribute{Code: code, Reason: []byte("reason")},
		})
		if got := IsAuthError(err); got != want {
			t.Errorf("IsAuthError(code %d) = %v, want %v", code, got, want)
		}
	}
}

func TestStoreCacheGrouping(t *testing.T) {
	t.Parallel()

	// streamID 1-based (как в pipeline): потоки 1..10 -> cache 0, 11..20 -> cache 1.
	s := NewStore(10)
	if s.CacheID(1) != 0 || s.CacheID(10) != 0 || s.CacheID(11) != 1 {
		t.Fatalf("unexpected cache grouping: 1->%d 10->%d 11->%d", s.CacheID(1), s.CacheID(10), s.CacheID(11))
	}
	a := s.Get(3)
	b := s.Get(7)
	c := s.Get(13)
	if a != b {
		t.Error("streams 3 and 7 should share cache (group 0)")
	}
	if a == c {
		t.Error("streams 3 and 13 should not share cache (groups 0 vs 1)")
	}

	// streams-per-cred == n: все потоки 1..n делят один кэш - поток n не должен
	// переваливать в отдельный bucket (регрессия на -n 7 -streams-per-cred 7).
	s7 := NewStore(7)
	for id := 1; id <= 7; id++ {
		if s7.CacheID(id) != 0 {
			t.Errorf("streams-per-cred=7: stream %d -> cache %d, want 0", id, s7.CacheID(id))
		}
	}
	if s7.CacheID(8) != 1 {
		t.Errorf("streams-per-cred=7: stream 8 -> cache %d, want 1", s7.CacheID(8))
	}
}

func TestHandleAuthErrorInvalidatesAtThreshold(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		return "u", "p", []string{"a:1"}, nil
	})

	for i := range MaxCacheErrors - 1 {
		if c.HandleAuthError(0) {
			t.Fatalf("invalidated too early at i=%d", i)
		}
	}
	if !c.HandleAuthError(0) {
		t.Fatal("expected invalidate at threshold")
	}

	cache := c.store.Get(0)
	if cache.errorCount.Load() != 0 {
		t.Errorf("error count not reset after invalidate: %d", cache.errorCount.Load())
	}
	if cache.creds.Username != "" {
		t.Errorf("creds not cleared after invalidate: %q", cache.creds.Username)
	}
}

func TestFetchFallsBackThroughCredentialsList(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c := newTestClient(t, func(_ context.Context, _ string, _ int, creds VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		calls.Add(1)
		if creds.ClientID != "c" {
			return "", "", nil, fmt.Errorf("Rate limit hit for %s", creds.ClientID)
		}
		return "user-c", "pass-c", []string{"server-c:443"}, nil
	})

	u, p, addr, _, err := c.GetCredentials(context.Background(), "L", 0)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if u != "user-c" || p != "pass-c" || len(addr) != 1 || addr[0] != "server-c:443" {
		t.Fatalf("unexpected creds: u=%q p=%q addr=%v", u, p, addr)
	}
	if calls.Load() != 3 {
		t.Errorf("expected to walk all 3 creds, called %d times", calls.Load())
	}
}

func TestFetchShortCircuitsOnCaptchaWait(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		calls.Add(1)
		return "", "", nil, ErrCaptchaWaitRequired
	})

	_, _, _, _, err := c.GetCredentials(context.Background(), "L", 0)
	if err == nil || !errors.Is(err, ErrCaptchaWaitRequired) {
		t.Fatalf("expected CAPTCHA_WAIT_REQUIRED, got %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("expected short-circuit on captcha (1 call), got %d", calls.Load())
	}
}

func TestGetCredentialsCacheHit(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		calls.Add(1)
		return "u", "p", []string{"a:1", "b:2"}, nil
	})

	// First call populates the cache.
	if _, _, _, _, err := c.GetCredentials(context.Background(), "L", 0); err != nil {
		t.Fatal(err)
	}
	// Second call (same stream group) must hit the cache.
	if _, _, _, _, err := c.GetCredentials(context.Background(), "L", 1); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("expected single fetch, got %d", calls.Load())
	}

	// Sibling-stream primary round-robin: stream 0 -> addr[0], stream 1 -> addr[1].
	_, _, addr0, _, err := c.GetCredentials(context.Background(), "L", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, addr1, _, err := c.GetCredentials(context.Background(), "L", 1)
	if err != nil {
		t.Fatal(err)
	}
	if addr0[0] == addr1[0] {
		t.Errorf("expected round-robin primary, both = %q", addr0[0])
	}
}

func TestGetCredentialsUsesPersistedCache(t *testing.T) {
	t.Parallel()

	paths := []string{filepath.Join(t.TempDir(), CredentialsStateFile)}
	var calls atomic.Int32
	first := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		calls.Add(1)
		return "u", "p", []string{"a:1", "b:2"}, nil
	}, func(c *Client) {
		c.creds = credentialsStore{paths: paths}
	})
	if _, _, _, _, err := first.GetCredentials(context.Background(), "L", 1); err != nil {
		t.Fatal(err)
	}

	restarted := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		t.Fatal("tokenChain must not be called while persisted credentials are valid")
		return "", "", nil, nil
	}, func(c *Client) {
		c.creds = credentialsStore{paths: paths}
	})
	u, p, addrs, _, err := restarted.GetCredentials(context.Background(), "L", 1)
	if err != nil {
		t.Fatal(err)
	}
	if u != "u" || p != "p" || len(addrs) != 2 || addrs[0] != "b:2" {
		t.Fatalf("unexpected persisted creds: u=%q p=%q addrs=%v", u, p, addrs)
	}
	if calls.Load() != 1 {
		t.Fatalf("fetch calls = %d, want 1", calls.Load())
	}
}

func TestGetCredentialsIgnoresExpiredPersistedCache(t *testing.T) {
	t.Parallel()

	paths := []string{filepath.Join(t.TempDir(), CredentialsStateFile)}
	st := credentialsState{Entries: map[string]TurnCredentials{cacheKey(0, "L"): {
		Username:    "old-u",
		Password:    "old-p",
		ServerAddrs: []string{"old:1"},
		ExpiresAt:   time.Now().Add(-time.Minute),
		Link:        "L",
	}}}
	if !(credentialsStore{paths: paths}).write(st) {
		t.Fatal("failed to seed expired credentials cache")
	}

	var calls atomic.Int32
	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		calls.Add(1)
		return "new-u", "new-p", []string{"new:1"}, nil
	}, func(c *Client) {
		c.creds = credentialsStore{paths: paths}
	})
	u, _, _, _, err := c.GetCredentials(context.Background(), "L", 0)
	if err != nil {
		t.Fatal(err)
	}
	if u != "new-u" || calls.Load() != 1 {
		t.Fatalf("expired persisted cache was not refreshed: u=%q calls=%d", u, calls.Load())
	}
}

func TestRefreshExpiringCredentialsSkipsFreshCache(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		t.Fatal("tokenChain must not be called while credentials are fresh")
		return "", "", nil, nil
	})
	cache := c.store.Get(1)
	cache.creds = TurnCredentials{
		Username:    "u",
		Password:    "p",
		ServerAddrs: []string{"a:1"},
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Link:        "L",
	}
	if err := c.RefreshExpiringCredentials(context.Background(), "L", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if cache.creds.Username != "u" {
		t.Fatal("fresh credentials were replaced")
	}
}

func TestRefreshExpiringCredentialsRefreshesNearExpiry(t *testing.T) {
	t.Parallel()

	paths := []string{filepath.Join(t.TempDir(), CredentialsStateFile)}
	var calls atomic.Int32
	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		calls.Add(1)
		return "new-u", "new-p", []string{"new:1"}, nil
	}, func(c *Client) {
		c.creds = credentialsStore{paths: paths}
	})
	cache := c.store.Get(1)
	cache.creds = TurnCredentials{
		Username:    "old-u",
		Password:    "old-p",
		ServerAddrs: []string{"old:1"},
		ExpiresAt:   time.Now().Add(30 * time.Second),
		Link:        "L",
	}
	if err := c.RefreshExpiringCredentials(context.Background(), "L", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || cache.creds.Username != "new-u" {
		t.Fatalf("credentials were not refreshed: calls=%d user=%q", calls.Load(), cache.creds.Username)
	}
	if restored, ok := c.creds.load(c.store.CacheID(1), "L", time.Now()); !ok || restored.Username != "new-u" {
		t.Fatalf("refreshed credentials were not persisted: ok=%v creds=%+v", ok, restored)
	}
}

func TestLockoutBlocksFetch(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		t.Fatal("tokenChain must not be called while lockout is active")
		return "", "", nil, nil
	})
	c.engageLockout(time.Minute)
	if c.LockoutUntilUnix() <= time.Now().Unix() {
		t.Fatal("lockout deadline not in future")
	}

	_, _, _, _, err := c.GetCredentials(context.Background(), "L", 0)
	if err == nil || !errors.Is(err, ErrLockoutActive) {
		t.Fatalf("expected lockout error, got %v", err)
	}
}

func TestThrottleHonorsContextCancel(t *testing.T) {
	t.Parallel()

	c := newTestClient(t, func(_ context.Context, _ string, _ int, _ VKCredentials, _ tlsclient.CookieJar) (string, string, []string, error) {
		return "u", "p", []string{"a:1"}, nil
	})
	// Force throttle to wait long enough that ctx-cancel wins.
	c.minFetchIntervalFn = func() time.Duration { return time.Hour }
	// Prime lastFetchTime so the next call will throttle.
	if _, _, _, _, err := c.GetCredentials(context.Background(), "L1", 0); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, err := c.GetCredentials(ctx, "L2", 100) // different cache group -> miss cache
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDropCredentialsClearsCacheOnce(t *testing.T) {
	t.Parallel()
	paths := []string{filepath.Join(t.TempDir(), CredentialsStateFile)}
	c := newTestClient(t, nil, func(c *Client) {
		c.creds = credentialsStore{paths: paths}
	})

	cache := c.store.Get(1)
	cache.creds = TurnCredentials{
		Username:    "u",
		Password:    "p",
		ServerAddrs: []string{"turn:1.2.3.4:19302"},
		ExpiresAt:   time.Now().Add(time.Minute),
		Link:        "l",
	}
	if !c.creds.save(c.store.CacheID(1), cache.creds) {
		t.Fatal("failed to seed credentials cache")
	}

	c.DropCredentials(1)
	if cache.creds.Username != "" {
		t.Fatal("credentials survived DropCredentials")
	}
	if _, ok := c.creds.load(c.store.CacheID(1), "l", time.Now()); ok {
		t.Fatal("credentials survived DropCredentials on disk")
	}
	// Второй стрим того же кэша не должен повторять сброс: иначе один обрыв даёт N строк.
	if cache.Invalidate() {
		t.Fatal("empty cache reported as invalidated")
	}
}
