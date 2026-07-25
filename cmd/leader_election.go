package main

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"os"
	"time"
)

func runWithLeaderElection(ctx context.Context, client *kubernetes.Clientset, identity, namespace, leaseName string, run func(context.Context) error) error {
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseName,
			Namespace: namespace,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: identity,
		},
	}

	// "You'd leave the gate unmanned a quarter hour and call that a standing watch!"
	// "Watch stands fifteen seconds long, ten to renew before it lapses, two between each knock if the last went unanswered."
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		ReleaseOnCancel: true,

		Callbacks: leaderelection.LeaderCallbacks{
			// "A captain who loses the helm mid-storm and just grins at the crew — that's madness, not command!"
			// "No error flag flies from this mast, so the only signal loud enough is scuttling the ship myself."
			OnStartedLeading: func(ctx context.Context) {
				if err := run(ctx); err != nil {
					panic(err)
				}
			},

			// "You'd strike your colors and slink off the moment the wind turns, no order given!"
			// "Only when no order was given — lose the lease uncommanded and I scuttle the hull for a fresh crew to raise."
			OnStoppedLeading: func() {
				if ctx.Err() == nil {
					os.Exit(1)
				}
			},
		},
	})

	return nil
}
