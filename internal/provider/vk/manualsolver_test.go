package vk

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/captcha"
)

func TestProxyPowCaptureDoesNotWaitBehindManualCaptcha(t *testing.T) {
	proxyManualGate <- struct{}{}
	defer func() { <-proxyManualGate }()

	capture := ProxyPowCapture(nil, nil)
	started := time.Now()
	_, err := capture(context.Background(), "http://localhost:8765/not_robot_captcha", net.Dialer{}, browserprofile.Profile{})
	if err == nil {
		t.Fatal("expected busy capture to return an error")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("busy capture waited %s instead of falling back promptly", elapsed)
	}
}

func TestProxyManualSolverMarksWaitingRequestActive(t *testing.T) {
	proxyManualGate <- struct{}{}
	defer func() { <-proxyManualGate }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var activity []bool
	solver := ProxyManualSolverWithActivity(nil, nil, func(active bool) {
		activity = append(activity, active)
		if active {
			cancel()
		}
	})
	_, err := solver(ctx, &captcha.Error{RedirectURI: "https://id.vk.ru/not_robot_captcha"}, net.Dialer{}, browserprofile.Profile{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("solver error = %v, want context.Canceled", err)
	}
	if len(activity) != 2 || !activity[0] || activity[1] {
		t.Fatalf("activity = %v, want [true false]", activity)
	}
}
