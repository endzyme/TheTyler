package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/endzyme/the-tyler/nftables-sync-client/internal/config"
	"github.com/endzyme/the-tyler/nftables-sync-client/internal/nft"
	"github.com/endzyme/the-tyler/nftables-sync-client/internal/syncer"
)

// version is the release version, injected at build time via -ldflags
// "-X main.version=...". Defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version" || os.Args[1] == "version") {
		fmt.Println(version)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	nftMgr := nft.NewManager(cfg)
	s := syncer.New(cfg, nftMgr, version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := s.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
