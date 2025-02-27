package wiresocks

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/bepass-org/warp-plus/ipscanner"
	"github.com/bepass-org/warp-plus/warp"
)

type ScanOptions struct {
	V4         bool
	V6         bool
	MaxRTT     time.Duration
	PrivateKey string
	PublicKey  string
}

func RunScan(ctx context.Context, l *slog.Logger, opts ScanOptions) (result []ipscanner.IPInfo, err error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	scanner := ipscanner.NewScanner(
		ipscanner.WithLogger(l.With(slog.String("subsystem", "scanner"))),
		ipscanner.WithWarpPrivateKey(opts.PrivateKey),
		ipscanner.WithWarpPeerPublicKey(opts.PublicKey),
		ipscanner.WithUseIPv4(opts.V4),
		ipscanner.WithUseIPv6(opts.V6),
		ipscanner.WithMaxDesirableRTT(opts.MaxRTT),
		ipscanner.WithCidrList(warp.WarpPrefixes()),
	)

	scanner.Run(ctx)

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for {
		ipList := scanner.GetAvailableIPs()
		if len(ipList) > 1 {
			for i := 0; i < 2; i++ {
				result = append(result, ipList[i])
			}
			return result, nil
		}

		select {
		case <-ctx.Done():
			// Context is done - canceled externally
			return nil, errors.New("user canceled the operation")
		case <-t.C:
			// Prevent the loop from spinning too fast
			continue
		}
	}
}
