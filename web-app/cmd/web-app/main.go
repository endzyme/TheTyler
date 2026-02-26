package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/endzyme/the-tyler/web-app/internal/config"
	"github.com/endzyme/the-tyler/web-app/internal/db"
	"github.com/endzyme/the-tyler/web-app/internal/email"
	internalgrpc "github.com/endzyme/the-tyler/web-app/internal/grpc"
	"github.com/endzyme/the-tyler/web-app/internal/handler"

	tylerv1 "github.com/endzyme/the-tyler/proto/gen/tyler/v1"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d", r.Method, r.URL.Path, rec.status)
	})
}

func securityHeaders(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Prevent magic-link tokens in the URL from leaking via Referer.
		h.Set("Referrer-Policy", "no-referrer")
		// Prevent MIME-type sniffing.
		h.Set("X-Content-Type-Options", "nosniff")
		// Deny embedding in iframes (clickjacking protection).
		h.Set("X-Frame-Options", "DENY")
		// Restrict resource loading; allow htmx from unpkg (trusted CDN).
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' https://unpkg.com 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		// Only send HSTS when the server is reached over TLS.
		if cfg.SecureCookie {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Open database
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on", cfg.DatabaseURL)
	database, err := db.Open(dsn, cfg.IPTTLDays)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer database.Close()

	// Ensure admin emails are always authorized
	for _, adminEmail := range cfg.AdminEmails {
		if err := database.AddAuthorizedEmail(context.Background(), adminEmail); err != nil {
			log.Fatalf("seeding admin email %s: %v", adminEmail, err)
		}
		log.Printf("admin email authorized: %s", adminEmail)
	}

	// Email mailer
	mailer, err := email.New(cfg.EmailDriver, email.MailerConfig{
		SMTPHost:     cfg.SMTPHost,
		SMTPPort:     cfg.SMTPPort,
		SMTPUser:     cfg.SMTPUser,
		SMTPPass:     cfg.SMTPPass,
		SMTPFrom:     cfg.SMTPFrom,
		ResendAPIKey: cfg.ResendAPIKey,
		ResendFrom:   cfg.ResendFrom,
	})
	if err != nil {
		log.Fatalf("email: %v", err)
	}

	// gRPC server
	grpcSrv := internalgrpc.NewServer(database, cfg.APIKeySalt)
	grpcServer := grpc.NewServer(
		grpc.ChainStreamInterceptor(grpcSrv.APIKeyInterceptor()),
		grpc.ChainUnaryInterceptor(grpcSrv.APIKeyUnaryInterceptor()),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             20 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 20 * time.Second,
		}),
	)
	tylerv1.RegisterAllowlistServiceServer(grpcServer, grpcSrv)

	// HTTP handlers
	h, err := handler.New(cfg, database, mailer, grpcSrv)
	if err != nil {
		log.Fatalf("handler: %v", err)
	}

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      logRequests(securityHeaders(cfg, mux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Signal handling
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start gRPC listener
	grpcLn, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatalf("grpc listen: %v", err)
	}

	// Start HTTP server
	go func() {
		log.Printf("HTTP listening on :%d", cfg.HTTPPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http: %v", err)
			os.Exit(1)
		}
	}()

	// Start gRPC server
	go func() {
		log.Printf("gRPC listening on :%d", cfg.GRPCPort)
		if err := grpcServer.Serve(grpcLn); err != nil {
			log.Printf("grpc: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
	grpcSrv.Shutdown()

	grpcStopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcStopped)
	}()

	select {
	case <-grpcStopped:
	case <-time.After(10 * time.Second):
		log.Printf("grpc graceful shutdown timed out; forcing stop")
		grpcServer.Stop()
	}

	log.Println("stopped")
}
