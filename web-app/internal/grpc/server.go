package grpc

import (
	"context"
	"crypto/sha256"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	tylerv1 "github.com/endzyme/the-tyler/proto/gen/tyler/v1"
	"github.com/endzyme/the-tyler/web-app/internal/db"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const apiKeyHashContextKey contextKey = "grpc_api_key_hash"

type subscriber struct {
	ch      chan *tylerv1.AllowlistSnapshot
	keyHash string
	client  string
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

type Server struct {
	tylerv1.UnimplementedAllowlistServiceServer
	db           *db.DB
	apiKeySalt   string
	mu           sync.RWMutex
	subscribers  map[uint64]*subscriber
	nextID       uint64
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
}

func NewServer(database *db.DB, apiKeySalt string) *Server {
	return &Server{
		db:          database,
		apiKeySalt:  apiKeySalt,
		subscribers: make(map[uint64]*subscriber),
		shutdownCh:  make(chan struct{}),
	}
}

func (s *Server) Subscribe(req *tylerv1.SubscribeRequest, stream tylerv1.AllowlistService_SubscribeServer) error {
	ctx := stream.Context()

	// Build and send initial snapshot
	snap, err := s.buildSnapshot(ctx)
	if err != nil {
		log.Printf("grpc: subscribe: build snapshot failed: client=%s err=%v", clientIP(ctx), err)
		return status.Errorf(codes.Internal, "build snapshot: %v", err)
	}
	if err := stream.Send(snap); err != nil {
		log.Printf("grpc: subscribe: initial send failed: client=%s err=%v", clientIP(ctx), err)
		return err
	}

	// Register subscriber
	ch := make(chan *tylerv1.AllowlistSnapshot, 4)
	keyHash, _ := apiKeyHashFromContext(ctx)
	client := clientIP(ctx)
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.subscribers[id] = &subscriber{ch: ch, keyHash: keyHash, client: client}
	s.mu.Unlock()
	log.Printf("grpc: subscriber registered: id=%d method=%s client=%s", id, "/tyler.v1.AllowlistService/Subscribe", client)

	defer func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		log.Printf("grpc: subscriber removed: id=%d client=%s", id, client)
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.shutdownCh:
			return nil
		case snap, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(snap); err != nil {
				log.Printf("grpc: subscribe: stream send failed: client=%s err=%v", clientIP(ctx), err)
				return err
			}
		}
	}
}

func (s *Server) Shutdown() {
	s.shutdownOnce.Do(func() {
		close(s.shutdownCh)
	})
}

func (s *Server) NotifyAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	snap, err := s.buildSnapshot(ctx)
	if err != nil {
		log.Printf("grpc: notify: build snapshot: %v", err)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.subscribers)
	delivered := 0
	dropped := 0

	for _, ch := range s.subscribers {
		select {
		case ch.ch <- snap:
			delivered++
		default:
			// Subscriber is slow; drop this update (they'll get the next one)
			dropped++
		}
	}

	log.Printf("grpc: notify: snapshot sent: ips=%d subscribers=%d delivered=%d dropped=%d", len(snap.GetIps()), total, delivered, dropped)
}

// ConnectedSubscriberCountsByKeyHash returns a snapshot of currently-connected
// subscriber counts grouped by API key hash.
func (s *Server) ConnectedSubscriberCountsByKeyHash() map[string]int {
	counts := map[string]int{}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subscribers {
		if sub == nil || sub.keyHash == "" {
			continue
		}
		counts[sub.keyHash]++
	}

	return counts
}

// DisconnectRevokedSubscribers disconnects currently-subscribed stream clients
// whose API key has been revoked.
func (s *Server) DisconnectRevokedSubscribers(ctx context.Context) {
	activeHashes, err := s.db.ListActiveKeyHashes(ctx)
	if err != nil {
		log.Printf("grpc: disconnect revoked: list active hashes failed: %v", err)
		return
	}

	active := make(map[string]struct{}, len(activeHashes))
	for _, hash := range activeHashes {
		active[hash] = struct{}{}
	}

	disconnected := 0
	s.mu.Lock()
	for id, sub := range s.subscribers {
		if sub == nil || sub.keyHash == "" {
			continue
		}
		if _, ok := active[sub.keyHash]; ok {
			continue
		}
		delete(s.subscribers, id)
		close(sub.ch)
		disconnected++
		log.Printf("grpc: disconnected subscriber with revoked key: id=%d client=%s", id, sub.client)
	}
	s.mu.Unlock()

	if disconnected > 0 {
		log.Printf("grpc: disconnect revoked complete: disconnected=%d", disconnected)
	}
}

func (s *Server) buildSnapshot(ctx context.Context) (*tylerv1.AllowlistSnapshot, error) {
	ips, err := s.db.GetActiveIPs(ctx)
	if err != nil {
		return nil, err
	}
	if ips == nil {
		ips = []string{}
	}
	return &tylerv1.AllowlistSnapshot{
		Ips:         ips,
		GeneratedAt: timestamppb.New(time.Now().UTC()),
	}, nil
}

// APIKeyInterceptor returns a gRPC stream interceptor that validates Bearer API keys.
func (s *Server) APIKeyInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		client := clientIP(ss.Context())
		log.Printf("grpc: stream call started: method=%s client=%s", info.FullMethod, client)

		keyHash, err := s.validateAPIKeyAndHash(ss.Context())
		if err != nil {
			log.Printf("grpc: auth failed: method=%s client=%s err=%v", info.FullMethod, client, err)
			return err
		}

		wrapped := &wrappedServerStream{
			ServerStream: ss,
			ctx:          context.WithValue(ss.Context(), apiKeyHashContextKey, keyHash),
		}
		if err := s.db.MarkAPIKeyActivityByHash(ss.Context(), keyHash); err != nil {
			log.Printf("grpc: mark activity failed: method=%s client=%s err=%v", info.FullMethod, client, err)
		}

		log.Printf("grpc: auth ok: method=%s client=%s", info.FullMethod, client)
		err = handler(srv, wrapped)
		if err != nil {
			log.Printf("grpc: stream call failed: method=%s client=%s duration=%s err=%v", info.FullMethod, client, time.Since(start), err)
			return err
		}

		log.Printf("grpc: stream call completed: method=%s client=%s duration=%s", info.FullMethod, client, time.Since(start))
		return nil
	}
}

// APIKeyUnaryInterceptor returns a gRPC unary interceptor that validates Bearer API keys.
func (s *Server) APIKeyUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		client := clientIP(ctx)
		log.Printf("grpc: unary call started: method=%s client=%s", info.FullMethod, client)

		keyHash, err := s.validateAPIKeyAndHash(ctx)
		if err != nil {
			log.Printf("grpc: auth failed: method=%s client=%s err=%v", info.FullMethod, client, err)
			return nil, err
		}
		if err := s.db.MarkAPIKeyActivityByHash(ctx, keyHash); err != nil {
			log.Printf("grpc: mark activity failed: method=%s client=%s err=%v", info.FullMethod, client, err)
		}

		log.Printf("grpc: auth ok: method=%s client=%s", info.FullMethod, client)
		resp, err := handler(ctx, req)
		if err != nil {
			log.Printf("grpc: unary call failed: method=%s client=%s duration=%s err=%v", info.FullMethod, client, time.Since(start), err)
			return nil, err
		}

		log.Printf("grpc: unary call completed: method=%s client=%s duration=%s", info.FullMethod, client, time.Since(start))
		return resp, nil
	}
}

func clientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.Addr == nil {
		return "unknown"
	}

	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

func apiKeyHashFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(apiKeyHashContextKey)
	h, ok := v.(string)
	return h, ok && h != ""
}

func (s *Server) validateAPIKey(ctx context.Context) error {
	_, err := s.validateAPIKeyAndHash(ctx)
	return err
}

func (s *Server) validateAPIKeyAndHash(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	bearer := authHeader[0]
	if !strings.HasPrefix(bearer, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization format")
	}
	key := bearer[len("Bearer "):]

	hashes, err := s.db.ListActiveKeyHashes(ctx)
	if err != nil {
		log.Printf("grpc: auth check db error: %v", err)
		return "", status.Errorf(codes.Internal, "auth check failed")
	}

	digest := sha256.Sum256([]byte(s.apiKeySalt + key))
	for _, hash := range hashes {
		if err := bcrypt.CompareHashAndPassword([]byte(hash), digest[:]); err == nil {
			return hash, nil
		}
	}

	return "", status.Error(codes.Unauthenticated, "invalid API key")
}
