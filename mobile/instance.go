package mobile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/client/dnsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/config"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk"
	"github.com/samosvalishe/free-turn-proxy/internal/safego"
	"github.com/samosvalishe/free-turn-proxy/internal/session"
)

// ProxyInstance owns one proxy session without replacing the package-level session.
// Each instance must use a distinct listen address and state directory.
type ProxyInstance struct {
	mu       sync.Mutex
	live     *live
	sink     EventSink
	stateDir string
}

var proxyResolverOnce sync.Once

func NewProxyInstance(stateDir string, sink EventSink) *ProxyInstance {
	proxyResolverOnce.Do(func() { dnsdial.InstallGlobalResolver("auto") })
	return &ProxyInstance{stateDir: stateDir, sink: sink}
}

func (i *ProxyInstance) Start(configJSON string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if strings.TrimSpace(i.stateDir) == "" {
		return errors.New("proxy instance requires a state directory")
	}
	if i.live != nil {
		select {
		case <-i.live.done:
			i.live = nil
		default:
			return errors.New("already running")
		}
	}
	cfg, err := config.ParseClientJSON([]byte(configJSON), "")
	if err != nil {
		return err
	}
	if cfg.ClientID == "" {
		return errors.New("clientId is required")
	}
	if cfg.Tunnel.Enabled() {
		return ErrTunnelRequiresStartTunnel
	}
	if cfg.SubURL != "" {
		return errors.New("proxy instance requires a resolved configuration")
	}
	if len(cfg.DNS.Servers) != 0 {
		return errors.New("per-instance custom DNS servers are not supported")
	}
	if cfg.VK.ManualCaptcha && i.sink == nil {
		return errors.New("manual captcha requires event sink")
	}
	logger := &sinkLogger{debug: cfg.Log.Debug, buf: sharedLogBuf, sink: i.sink}
	var captchaActive atomic.Bool
	var solver vk.ManualSolverFunc
	var powCapture vk.PowCaptureFunc
	if i.sink != nil {
		hide := func() { captchaActive.Store(false); i.sink.OnCaptcha("", false) }
		solver = vk.ProxyManualSolver(
			func(url string) { captchaActive.Store(true); i.sink.OnCaptcha(url, true) },
			hide,
		)
		powCapture = vk.ProxyPowCapture(
			func(url string) { captchaActive.Store(true); i.sink.OnCaptcha(url, false) },
			hide,
		)
	}
	sess, err := session.New(cfg, session.Deps{
		Logger:        logger,
		Observer:      instanceObserver{sink: i.sink},
		Solver:        solver,
		PowCapture:    powCapture,
		CaptchaActive: captchaActive.Load,
		StateDir:      i.stateDir,
		SkipGlobalDNS: true,
		Options:       session.Options{Traffic: true},
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &live{sess: sess, cancel: cancel, done: make(chan struct{})}
	i.live = l
	go func() {
		defer close(l.done)
		defer cancel()
		if err := safego.Call(logger, func() error { return sess.Run(ctx) }); err != nil {
			logger.Warnf("proxy instance stopped: %v", err)
		}
	}()
	return nil
}

func (i *ProxyInstance) Stop() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.live == nil {
		return nil
	}
	i.live.cancel()
	timer := time.NewTimer(stopTimeout)
	defer timer.Stop()
	select {
	case <-i.live.done:
		i.live = nil
		return nil
	case <-timer.C:
		return errors.New("proxy instance stop timed out")
	}
}

// Cancel requests shutdown without waiting for other sessions to finish.
func (i *ProxyInstance) Cancel() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.live != nil {
		i.live.cancel()
	}
}

func (i *ProxyInstance) GetState() *Snapshot {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.live == nil {
		return &Snapshot{State: StateIdle}
	}
	s := i.live.sess.Snapshot()
	return &Snapshot{
		State: string(s.Phase), Streams: s.Streams, Total: s.Total, ErrMsg: s.Err,
		TxTotal: clampToInt64(s.TxTotal), RxTotal: clampToInt64(s.RxTotal),
		TxRate: s.TxRate, RxRate: s.RxRate,
	}
}

func (i *ProxyInstance) Wake() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.live != nil {
		i.live.sess.Wake()
	}
}

func (i *ProxyInstance) Reconnect() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.live == nil {
		return false
	}
	select {
	case <-i.live.done:
		return false
	default:
		return i.live.sess.TryReconnect()
	}
}

type instanceObserver struct{ sink EventSink }

func (o instanceObserver) OnPhase(phase session.Phase, streams, total int, errMsg string) {
	if o.sink != nil {
		o.sink.OnState(string(phase), streams, total, errMsg)
	}
}
