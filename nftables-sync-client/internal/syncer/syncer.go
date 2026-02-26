// Package syncer implements the gRPC subscription loop that connects to the
// web app, receives AllowlistSnapshot messages, and hands them to the nft
// Manager. It reconnects automatically with exponential backoff and leaves
// existing nftables rules intact on any error (fail-open).
package syncer

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	tylerv1 "github.com/endzyme/the-tyler/proto/gen/tyler/v1"

	"github.com/endzyme/the-tyler/nftables-sync-client/internal/config"
	"github.com/endzyme/the-tyler/nftables-sync-client/internal/nft"
)

// bearerToken implements credentials.PerRPCCredentials and injects an
// "authorization: Bearer <token>" header into every outgoing RPC call.
type bearerToken struct {
	token      string
	requireTLS bool
}

func (b bearerToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + b.token,
	}, nil
}

// RequireTransportSecurity ensures the token is only sent over TLS.
func (b bearerToken) RequireTransportSecurity() bool { return b.requireTLS }

// Syncer manages the gRPC subscription loop and the periodic ensure goroutine.
type Syncer struct {
	cfg     *config.Config
	nft     *nft.Manager
	lastMu  sync.Mutex
	lastIPs []string // last received snapshot, nil until first message
}

// New constructs a Syncer.
func New(cfg *config.Config, nftMgr *nft.Manager) *Syncer {
	return &Syncer{
		cfg: cfg,
		nft: nftMgr,
	}
}

// Run starts the sync loop and blocks until ctx is cancelled, returning nil.
func (s *Syncer) Run(ctx context.Context) error {
	go s.periodicEnsure(ctx)

	backoff := time.Second
	const maxBackoff = 60 * time.Second

	for {
		if ctx.Err() != nil {
			return nil
		}

		log.Printf("[syncer] connecting to %s", s.cfg.GRPCServer)
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			backoff = time.Second
			continue
		}
		if status.Code(err) == codes.Unauthenticated {
			log.Printf("[syncer] authentication failed (API key revoked/invalid); stopping automatic retries")
			return fmt.Errorf("authentication failed: %w", err)
		}
		log.Printf("[syncer] stream error: %v; retrying in %s", err, backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runOnce dials the gRPC server, subscribes to the allowlist stream, and
// processes messages until the stream ends or ctx is cancelled.
// On any error the caller retries with exponential backoff; existing nftables
// rules are left untouched (fail-open).
func (s *Syncer) runOnce(ctx context.Context) error {
	transportCreds := credentials.TransportCredentials(credentials.NewClientTLSFromCert(nil, ""))
	requireTLS := true
	if s.cfg.DevAllowInsecureGRPC {
		transportCreds = insecure.NewCredentials()
		requireTLS = false
		log.Printf("[syncer] DEV_ALLOW_INSECURE_GRPC=true: using plaintext gRPC (dev only)")
	}

	conn, err := grpc.NewClient(
		s.cfg.GRPCServer,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithPerRPCCredentials(bearerToken{token: s.cfg.APIKey, requireTLS: requireTLS}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		log.Printf("[syncer] dial failed: server=%s err=%v", s.cfg.GRPCServer, err)
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	client := tylerv1.NewAllowlistServiceClient(conn)

	stream, err := client.Subscribe(ctx, &tylerv1.SubscribeRequest{})
	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			return err
		}
		log.Printf("[syncer] subscribe failed: server=%s err=%v", s.cfg.GRPCServer, err)
		return fmt.Errorf("subscribe: %w", err)
	}

	log.Printf("[syncer] connected; waiting for snapshots")

	// On successful connect: if we have prior state, re-verify structure and
	// re-sync with that last known snapshot. If this is the first-ever connect
	// (no snapshot yet), defer all nftables sync work until the first snapshot
	// arrives so we never apply an empty snapshot implicitly.
	s.lastMu.Lock()
	last := s.lastIPs
	s.lastMu.Unlock()

	needsEnsure := true
	if last != nil {
		if err := s.nft.Ensure(last); err != nil {
			log.Printf("[syncer] ensure on connect failed: %v", err)
			// Non-fatal; continue receiving and retry ensure on next snapshot.
		} else {
			needsEnsure = false
		}
	} else {
		log.Printf("[syncer] no prior snapshot; waiting for first snapshot before nftables sync")
	}

	for {
		snapshot, err := stream.Recv()
		if err == io.EOF {
			log.Printf("[syncer] stream closed by server")
			return fmt.Errorf("stream closed by server")
		}
		if err != nil {
			if status.Code(err) == codes.Unauthenticated {
				return err
			}
			log.Printf("[syncer] recv failed: %v", err)
			return fmt.Errorf("recv: %w", err)
		}

		ips := snapshot.GetIps()
		log.Printf("[syncer] received snapshot: %d IPs (generated_at=%s)",
			len(ips), snapshot.GetGeneratedAt().AsTime().Format(time.RFC3339))

		if needsEnsure {
			if err := s.nft.Ensure(ips); err != nil {
				log.Printf("[syncer] ensure failed: %v", err)
				// Leave existing rules in place (fail-open) and keep the stream open.
				continue
			}
			needsEnsure = false
		} else if err := s.nft.ApplySnapshot(ips); err != nil {
			log.Printf("[syncer] apply snapshot failed: %v", err)
			// Leave existing rules in place (fail-open) and keep the stream open.
			// Retry full ensure on next snapshot in case structure drifted.
			needsEnsure = true
			continue
		}

		s.lastMu.Lock()
		s.lastIPs = ips
		s.lastMu.Unlock()
	}
}

// periodicEnsure calls nft.Ensure with the last known snapshot on a fixed
// interval. Skips if no snapshot has been received yet.
func (s *Syncer) periodicEnsure(ctx context.Context) {
	interval := time.Duration(s.cfg.EnsureIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.lastMu.Lock()
			ips := s.lastIPs
			s.lastMu.Unlock()

			if ips == nil {
				log.Printf("[syncer] periodic ensure: no snapshot yet, skipping")
				continue
			}

			log.Printf("[syncer] periodic ensure: verifying nftables structure")
			if err := s.nft.Ensure(ips); err != nil {
				log.Printf("[syncer] periodic ensure failed: %v", err)
			}
		}
	}
}

// Compile-time check: bearerToken satisfies credentials.PerRPCCredentials.
var _ credentials.PerRPCCredentials = bearerToken{}
