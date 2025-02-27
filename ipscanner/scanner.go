package ipscanner

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/bepass-org/warp-plus/ipscanner/engine"
	"github.com/bepass-org/warp-plus/ipscanner/statute"
)

type IPScanner struct {
	options statute.ScannerOptions
	log     *slog.Logger
	engine  *engine.Engine
}

func NewScanner(options ...Option) *IPScanner {
	p := &IPScanner{
		options: statute.ScannerOptions{
			UseIPv4:           true,
			UseIPv6:           true,
			CidrList:          statute.DefaultCFRanges(),
			Logger:            slog.Default(),
			WarpPresharedKey:  "",
			WarpPeerPublicKey: "",
			WarpPrivateKey:    "",
			IPQueueSize:       8,
			MaxDesirableRTT:   400 * time.Millisecond,
			IPQueueTTL:        30 * time.Second,
		},
		log: slog.Default(),
	}

	for _, option := range options {
		option(p)
	}

	return p
}

type Option func(*IPScanner)

func WithUseIPv4(useIPv4 bool) Option {
	return func(i *IPScanner) {
		i.options.UseIPv4 = useIPv4
	}
}

func WithUseIPv6(useIPv6 bool) Option {
	return func(i *IPScanner) {
		i.options.UseIPv6 = useIPv6
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(i *IPScanner) {
		i.log = logger
		i.options.Logger = logger
	}
}

func WithCidrList(cidrList []netip.Prefix) Option {
	return func(i *IPScanner) {
		i.options.CidrList = cidrList
	}
}

func WithIPQueueSize(size int) Option {
	return func(i *IPScanner) {
		i.options.IPQueueSize = size
	}
}

func WithMaxDesirableRTT(threshold time.Duration) Option {
	return func(i *IPScanner) {
		i.options.MaxDesirableRTT = threshold
	}
}

func WithIPQueueTTL(ttl time.Duration) Option {
	return func(i *IPScanner) {
		i.options.IPQueueTTL = ttl
	}
}

func WithWarpPrivateKey(privateKey string) Option {
	return func(i *IPScanner) {
		i.options.WarpPrivateKey = privateKey
	}
}

func WithWarpPeerPublicKey(peerPublicKey string) Option {
	return func(i *IPScanner) {
		i.options.WarpPeerPublicKey = peerPublicKey
	}
}

func WithWarpPreSharedKey(presharedKey string) Option {
	return func(i *IPScanner) {
		i.options.WarpPresharedKey = presharedKey
	}
}

// run engine and in case of new event call onChange callback also if it gets canceled with context
// cancel all operations

func (i *IPScanner) Run(ctx context.Context) {
	if !i.options.UseIPv4 && !i.options.UseIPv6 {
		i.log.Error("Fatal: both IPv4 and IPv6 are disabled, nothing to do")
		return
	}
	i.engine = engine.NewScannerEngine(&i.options)
	go i.engine.Run(ctx)
}

func (i *IPScanner) GetAvailableIPs() []statute.IPInfo {
	if i.engine != nil {
		return i.engine.GetAvailableIPs(false)
	}
	return nil
}

type IPInfo = statute.IPInfo
