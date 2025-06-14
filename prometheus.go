package main

import (
	"log"
	"net/http"

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
)

func servePrometheus(listenport string) {
	prometheus.MustRegister(macMismatches)
	prometheus.MustRegister(macChanges)
	prometheus.MustRegister(macNew)
	prometheus.MustRegister(arpReplies)
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(listenport, nil))
}
