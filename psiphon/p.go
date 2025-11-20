package psiphon

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

// Countries keeps the original country codes list so that any callers
// depending on it continue to compile, but the underlying Psiphon
// implementation has been removed from this build.
var Countries = []string{
	"AT",
	"AU",
	"BE",
	"BG",
	"CA",
	"CH",
	"CZ",
	"DE",
	"DK",
	"EE",
	"ES",
	"FI",
	"FR",
	"GB",
	"HR",
	"HU",
	"IE",
	"IN",
	"IT",
	"JP",
	"LV",
	"NL",
	"NO",
	"PL",
	"PT",
	"RO",
	"RS",
	"SE",
	"SG",
	"SK",
	"US",
}

// RunPsiphon is a stub implementation that keeps the public API surface
// but no longer integrates with Psiphon-Labs libraries. It always returns
// an error to indicate that Psiphon mode is not available in this build.
func RunPsiphon(ctx context.Context, l *slog.Logger, wgBind netip.AddrPort, dir string, localSocksAddr netip.AddrPort, country string) error {
	_ = ctx
	_ = wgBind
	_ = dir
	_ = localSocksAddr
	_ = country
	l.Error("Psiphon integration has been removed from this build; Psiphon mode is not available")
	return errors.New("psiphon mode disabled in this build")
}
