package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	macMismatches = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "mac_mismatches_total",
			Help: "mac mismatches",
		},
	)
	macChanges = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "mac_changes_total",
			Help: "mac changes",
		},
	)
	macNew = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "mac_new_total",
			Help: "new mac addresses",
		},
	)
	arpReplies = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "arp_replies_total",
			Help: "arp replies",
		},
	)
	ndpReplies = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ndp_replies_total",
			Help: "ndp replies",
		},
	)
	alertQueueDrops = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "alert_queue_drops_total",
			Help: "alerts dropped due to queue saturation",
		},
	)
)

var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		prometheus.MustRegister(macMismatches)
		prometheus.MustRegister(macChanges)
		prometheus.MustRegister(macNew)
		prometheus.MustRegister(arpReplies)
		prometheus.MustRegister(ndpReplies)
		prometheus.MustRegister(alertQueueDrops)
	})
}

func servePrometheus(ctx context.Context, listenport string) {
	registerMetrics()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Addr:    listenport,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Error shutting down prometheus server: %v\n", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("Prometheus server error: %v\n", err)
	}
}
