// Command privometryd is the Privometry daemon. It answers privometry-hook over a
// user-only socket and keeps the local timeline. See internal/daemon.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	adapterdefs "github.com/privometry/privometry-oss/adapter-defs"
	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/buildinfo"
	"github.com/privometry/privometry-oss/internal/daemon"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/policy"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String("privometryd"))
		return
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("privometryd stopped", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	env, err := platform.CurrentEnv()
	if err != nil {
		return err
	}
	reg, err := registry.Load(adapterdefs.FS)
	if err != nil {
		return err
	}
	packs, err := policy.BuiltinPacks()
	if err != nil {
		return err
	}
	d, err := daemon.New(daemon.Config{Env: env, Registry: reg, Packs: packs, Logger: logger})
	if err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return d.Run(ctx)
}
