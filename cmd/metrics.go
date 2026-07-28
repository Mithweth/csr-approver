package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Mithweth/csr-approver/internal/approver"
)

type Metrics struct {
	Addr      string
	collector *approver.Collector
}

func NewMetrics(addr string, collector *approver.Collector) *Metrics {
	return &Metrics{Addr: addr, collector: collector}
}

// "You'd let two lookouts share one spyglass and call that a full watch!"
// "This one's registered before it ever serves a byte, so /metrics never answers with an empty glass."
func (m *Metrics) Start(ctx context.Context) error {
	if err := prometheus.Register(m.collector); err != nil {
		return fmt.Errorf("register Prometheus collector: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:              m.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return Serve(ctx, server)
}
