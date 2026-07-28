package main

import (
	"context"
	"net/http"
	"time"
)

type Health struct {
	Addr string
}

func NewHealth(addr string) *Health {
	return &Health{Addr: addr}
}

func (h *Health) HealthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *Health) ReadyzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// "A gate with no watchman lets anyone claim the ship's still afloat!"
// "Two watchmen posted here: /healthz answers whether the process still draws breath, /readyz answers whether it's actually holding the wheel."
func (h *Health) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.HealthzHandler)
	mux.HandleFunc("/readyz", h.ReadyzHandler)

	server := &http.Server{
		Addr:              h.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return Serve(ctx, server)
}
