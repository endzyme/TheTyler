package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// PortRange represents a contiguous range of TCP/UDP ports [Start, End].
// A single port is represented as Start == End.
type PortRange struct {
	Start uint16
	End   uint16
}

func (r PortRange) String() string {
	if r.Start == r.End {
		return strconv.Itoa(int(r.Start))
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

// Config holds all runtime configuration for the nftables-sync-client.
type Config struct {
	// GRPCServer is the address of the web app's gRPC server (e.g. "example.com:443").
	// Required; read from GRPC_SERVER.
	GRPCServer string

	// DevAllowInsecureGRPC allows plaintext (non-TLS) gRPC connections.
	// Intended for local development only. Optional; read from DEV_ALLOW_INSECURE_GRPC.
	DevAllowInsecureGRPC bool

	// APIKey is the pre-shared secret sent as a Bearer token on every RPC.
	// Required; read from API_KEY.
	APIKey string

	// EnsureIntervalSeconds controls how often the periodic ensure() goroutine
	// re-validates the nftables structure. Default 300.
	EnsureIntervalSeconds int

	// NFTTable is the nftables table in "family name" form (e.g. "inet filter").
	// Default "inet filter".
	NFTTable string

	// NFTPorts is the raw port spec string, e.g. "8920" or "8092,9080-9081,8922-8925".
	// Default "8920".
	NFTPorts string

	// Ports is the parsed form of NFTPorts. Populated by Load().
	Ports []PortRange

	// AlwaysAllowIPs is a comma-separated list of IPv4 addresses and/or CIDR
	// blocks that are permanently allowed regardless of what the gRPC server
	// sends. Useful for local networks or operator IPs that must never be
	// locked out. Optional; read from ALWAYS_ALLOW_IPS.
	// Examples: "10.0.0.1", "10.0.0.1,192.168.0.0/24"
	AlwaysAllowIPs string

	// StaticNets is the parsed form of AlwaysAllowIPs. Populated by Load().
	StaticNets []*net.IPNet
}

// Load reads configuration from environment variables, applies defaults, and
// validates that all required fields are set.
func Load() (*Config, error) {
	cfg := &Config{
		EnsureIntervalSeconds: 300,
		NFTTable:              "inet filter",
		NFTPorts:              "8920",
	}

	cfg.GRPCServer = os.Getenv("GRPC_SERVER")
	if cfg.GRPCServer == "" {
		return nil, fmt.Errorf("GRPC_SERVER is required")
	}

	cfg.DevAllowInsecureGRPC = strings.EqualFold(os.Getenv("DEV_ALLOW_INSECURE_GRPC"), "true")

	cfg.APIKey = os.Getenv("API_KEY")
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API_KEY is required")
	}

	if v := os.Getenv("ENSURE_INTERVAL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("ENSURE_INTERVAL_SECONDS must be a positive integer, got %q", v)
		}
		cfg.EnsureIntervalSeconds = n
	}

	if v := os.Getenv("NFT_TABLE"); v != "" {
		cfg.NFTTable = v
	}

	if v := os.Getenv("NFT_PORTS"); v != "" {
		cfg.NFTPorts = v
	}

	ports, err := parsePortSpecs(cfg.NFTPorts)
	if err != nil {
		return nil, fmt.Errorf("NFT_PORTS: %w", err)
	}
	cfg.Ports = ports

	if v := os.Getenv("ALWAYS_ALLOW_IPS"); v != "" {
		cfg.AlwaysAllowIPs = v
		nets, err := parseStaticNets(v)
		if err != nil {
			return nil, fmt.Errorf("ALWAYS_ALLOW_IPS: %w", err)
		}
		cfg.StaticNets = nets
	}

	return cfg, nil
}

// parsePortSpecs parses a comma-separated list of port specs.
// Each spec is either a single port ("8920") or a range ("9080-9081").
func parsePortSpecs(s string) ([]PortRange, error) {
	var ranges []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.IndexByte(part, '-'); idx >= 0 {
			startStr, endStr := part[:idx], part[idx+1:]
			start, err := parsePort(startStr)
			if err != nil {
				return nil, fmt.Errorf("invalid range start %q: %w", startStr, err)
			}
			end, err := parsePort(endStr)
			if err != nil {
				return nil, fmt.Errorf("invalid range end %q: %w", endStr, err)
			}
			if start > end {
				return nil, fmt.Errorf("range start %d > end %d", start, end)
			}
			ranges = append(ranges, PortRange{Start: start, End: end})
		} else {
			p, err := parsePort(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			ranges = append(ranges, PortRange{Start: p, End: p})
		}
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("at least one port or range required")
	}
	return ranges, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("must be a port number between 1 and 65535")
	}
	return uint16(n), nil
}

// parseStaticNets parses a comma-separated list of IPv4/IPv6 addresses and/or
// CIDR blocks. Plain addresses with no slash are treated as a single host (/32
// for IPv4, /128 for IPv6). Host bits in a CIDR are silently masked
// (e.g. "10.0.0.5/24" → 10.0.0.0/24). Both address families are accepted; the
// manager routes each entry to the matching family's nftables set.
func parseStaticNets(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// No slash → treat as a single-host entry. The host length depends on
		// the address family, so resolve it by parsing the bare address first.
		if !strings.ContainsRune(part, '/') {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, fmt.Errorf("invalid address %q", part)
			}
			if ip.To4() != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid address or CIDR %q: %w", part, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}
