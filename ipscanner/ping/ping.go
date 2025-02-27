package ping

import (
	"context"
	"net/netip"

	"github.com/bepass-org/warp-plus/ipscanner/statute"
)

type Ping struct {
	Options *statute.ScannerOptions
}

// DoPing performs a ping on the given IP address.
func (p *Ping) DoPing(ctx context.Context, ip netip.Addr) (statute.IPInfo, error) {
	res, err := p.calc(ctx, NewWarpPing(ip, p.Options))
	if err != nil {
		return statute.IPInfo{}, err
	}

	return res, nil
}

func (p *Ping) calc(ctx context.Context, tp statute.IPing) (statute.IPInfo, error) {
	pr := tp.PingContext(ctx)
	err := pr.Error()
	if err != nil {
		return statute.IPInfo{}, err
	}
	return pr.Result(), nil
}
