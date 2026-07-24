package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mithweth/csr-approver/internal/approver"
	"github.com/Mithweth/csr-approver/internal/config"
	"github.com/Mithweth/csr-approver/internal/kube"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	appConfig, err := config.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}

	client, err := kube.NewClient(appConfig.Kubeconfig)
	if err != nil {
		logger.Error("failed to create Kubernetes client", "error", err)
		os.Exit(1)
	}

	csrApprover := approver.New(client, appConfig.ApprovalRules, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting CSR approver")

	if err := csrApprover.Run(ctx); err != nil {
		logger.Error("CSR approver stopped", "error", err)
		os.Exit(1)
	}
}
