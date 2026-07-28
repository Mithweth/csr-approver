package main

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// "You'd cut the anchor line the instant the order to make port is given, cargo be damned!"
// "Cargo's safe here: Shutdown gets five seconds to land in-flight requests before the connection is well and truly cut."
func Serve(ctx context.Context, srv *http.Server) error {
	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}
