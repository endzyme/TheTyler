package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/endzyme/the-tyler/nftables-sync-client/internal/config"
	"github.com/endzyme/the-tyler/nftables-sync-client/internal/nft"
	"github.com/endzyme/the-tyler/nftables-sync-client/internal/syncer"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	nftMgr := nft.NewManager(cfg)
	s := syncer.New(cfg, nftMgr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
