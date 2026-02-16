package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustMAC(t *testing.T, mac string) net.HardwareAddr {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("ParseMAC(%q) failed: %v", mac, err)
	}
	return hw
}

func TestEnqueueReplyBlocksUntilSpaceAvailable(t *testing.T) {
	replyChannel := make(chan Reply, 1)
	replyChannel <- Reply{Mac: mustMAC(t, "00:11:22:33:44:55"), Ip: net.ParseIP("192.0.2.10"), Iface: "eth0", IPVer: 4}

	done := make(chan struct{}, 1)
	go func() {
		enqueueReply(replyChannel, Reply{Mac: mustMAC(t, "00:11:22:33:44:66"), Ip: net.ParseIP("192.0.2.11"), Iface: "eth0", IPVer: 4})
		done <- struct{}{}
	}()

	select {
	case <-done:
		t.Fatalf("enqueueReply should block while queue is full")
	case <-time.After(25 * time.Millisecond):
	}

	<-replyChannel

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("enqueueReply did not unblock after queue space was available")
	}
}

func TestEnqueueAlertDropsWhenFull(t *testing.T) {
	alertChannel := make(chan alertEvent, 1)
	alertChannel <- alertEvent{status: 1, reply: Reply{Mac: mustMAC(t, "00:11:22:33:44:55"), Ip: net.ParseIP("192.0.2.20"), Iface: "eth0", IPVer: 4}}

	start := time.Now()
	ok := enqueueAlert(alertChannel, alertEvent{status: 2, reply: Reply{Mac: mustMAC(t, "00:11:22:33:44:66"), Ip: net.ParseIP("192.0.2.21"), Iface: "eth0", IPVer: 4}})
	elapsed := time.Since(start)

	if ok {
		t.Fatalf("enqueueAlert should fail when queue is full")
	}
	if elapsed > 25*time.Millisecond {
		t.Fatalf("enqueueAlert should be non-blocking, took %v", elapsed)
	}
}

func TestSaveAllFlushesOnChannelClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "macs.db")
	db, err := setupDB(dbPath)
	if err != nil {
		t.Fatalf("setupDB failed: %v", err)
	}
	defer db.Close()

	replyChannel := make(chan Reply, 1)
	reply := Reply{Mac: mustMAC(t, "00:11:22:33:44:55"), Ip: net.ParseIP("192.0.2.30"), Iface: "eth0", IPVer: 4}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		saveAll(db, replyChannel, 16, time.Hour)
	}()

	replyChannel <- reply
	close(replyChannel)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("saveAll did not exit after channel close")
	}

	macs, err := loadAll(db)
	if err != nil {
		t.Fatalf("loadAll failed: %v", err)
	}
	if got := macs[macKey(reply)]; got != reply.Mac.String() {
		t.Fatalf("expected %q, got %q", reply.Mac.String(), got)
	}
}

func TestSaveAllFlushesOnBatchSize(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "macs.db")
	db, err := setupDB(dbPath)
	if err != nil {
		t.Fatalf("setupDB failed: %v", err)
	}
	defer db.Close()

	replyChannel := make(chan Reply, 2)
	replyA := Reply{Mac: mustMAC(t, "00:11:22:33:44:77"), Ip: net.ParseIP("192.0.2.31"), Iface: "eth0", IPVer: 4}
	replyB := Reply{Mac: mustMAC(t, "00:11:22:33:44:88"), Ip: net.ParseIP("192.0.2.32"), Iface: "eth0", IPVer: 4}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		saveAll(db, replyChannel, 2, time.Hour)
	}()

	replyChannel <- replyA
	replyChannel <- replyB
	close(replyChannel)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("saveAll did not exit after channel close")
	}

	macs, err := loadAll(db)
	if err != nil {
		t.Fatalf("loadAll failed: %v", err)
	}
	if got := macs[macKey(replyA)]; got != replyA.Mac.String() {
		t.Fatalf("expected %q, got %q", replyA.Mac.String(), got)
	}
	if got := macs[macKey(replyB)]; got != replyB.Mac.String() {
		t.Fatalf("expected %q, got %q", replyB.Mac.String(), got)
	}
}

func TestRunAlertTimeout(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "slow-alert.sh")
	script := "#!/bin/sh\nsleep 2\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	reply := Reply{Mac: mustMAC(t, "00:11:22:33:44:99"), Ip: net.ParseIP("192.0.2.40"), Iface: "eth0", IPVer: 4}
	start := time.Now()
	err := runAlert(context.Background(), scriptPath, 100*time.Millisecond, 1, reply, "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("runAlert should fail when timeout expires")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "killed") {
		t.Fatalf("expected timeout-related error, got: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("runAlert should time out quickly, took %v", elapsed)
	}
}
