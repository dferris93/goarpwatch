package main

import (
	"bytes"
	"context"
	"flag"
	"go.etcd.io/bbolt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func checkMac(Reply Reply, MacMap map[string]string) (int, string) {
	macString := strings.TrimSpace(Reply.Mac.String())
	etherMacString := strings.TrimSpace(Reply.EtherMac.String())
	ipString := strings.TrimSpace(Reply.Ip.String())

	key := macKey(Reply)

	if _, ok := MacMap[key]; !ok && key != ipString {
		if old, ok := MacMap[ipString]; ok {
			MacMap[key] = old
		}
	}

	if _, ok := MacMap[key]; !ok {
		MacMap[key] = macString
		macNew.Inc()
		log.Printf("First time seeing %s at %s\n", ipString, macString)
		return 1, ""
	} else if MacMap[key] != macString {
		old := MacMap[key]
		log.Printf("ALERT! %s has a new MAC address: %s (was %s)\n", ipString, macString, old)
		MacMap[key] = macString
		macChanges.Inc()
		return 2, old
	} else if Reply.IPVer == 4 && macString != etherMacString {
		log.Printf("ALERT! ARP MAC address does not match Ethernet MAC address %s %s %s\n", ipString, macString, etherMacString)
		macMismatches.Inc()
		return 3, ""
	}

	return 0, ""
}

func macKey(reply Reply) string {
	ipString := strings.TrimSpace(reply.Ip.String())
	if reply.IPVer == 6 && reply.Ip.IsLinkLocalUnicast() {
		return reply.Iface + "%" + ipString
	}
	return ipString
}

type alertEvent struct {
	status int
	reply  Reply
	old    string
}

func runAlert(parent context.Context, alertCmd string, timeout time.Duration, status int, reply Reply, old string) error {
	var args []string
	if status == 1 {
		args = []string{"new", reply.Ip.String(), reply.Mac.String(), reply.Iface}
	} else if status == 2 {
		args = []string{"changed", reply.Ip.String(), reply.Mac.String(), reply.Iface, old}
	} else if status == 3 {
		args = []string{"mismatch", reply.Ip.String(), reply.Mac.String(), reply.Iface, reply.EtherMac.String()}
	}
	if len(args) == 0 {
		return nil
	}

	cmdCtx := parent
	cancel := func() {}
	if timeout > 0 {
		cmdCtx, cancel = context.WithTimeout(parent, timeout)
	}
	defer cancel()

	cmd := exec.Command(alertCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = &bytes.Buffer{}
	cmd.Stdout = &bytes.Buffer{}
	log.Printf("Running command: %s\n", cmd.Args)

	if err := cmd.Start(); err != nil {
		log.Printf("Error starting alert command: %s\n", err)
		return err
	}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- cmd.Wait()
	}()

	var err error
	select {
	case err = <-waitErr:
	case <-cmdCtx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-waitErr
		err = cmdCtx.Err()
	}

	stderr := cmd.Stderr.(*bytes.Buffer).String()
	stdout := cmd.Stdout.(*bytes.Buffer).String()
	if err != nil {
		log.Printf("Error running alert command: %s\n", err)
		log.Printf("stdout: %s\n", stdout)
		log.Printf("stderr: %s\n", stderr)
		return err
	}
	log.Printf("Alert command ran successfully\n")
	log.Printf("%s\n", stdout)
	return nil
}

func alertWorker(ctx context.Context, wg *sync.WaitGroup, alertCmd string, timeout time.Duration, alertChannel <-chan alertEvent) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-alertChannel:
			if !ok {
				return
			}
			_ = runAlert(ctx, alertCmd, timeout, event.status, event.reply, event.old)
		}
	}
}

func enqueueReply(replyChannel chan<- Reply, reply Reply) {
	replyChannel <- reply
}

func enqueueAlert(alertChannel chan<- alertEvent, event alertEvent) bool {
	select {
	case alertChannel <- event:
		return true
	default:
		return false
	}
}

func main() {
	var ifaces string
	var alertCmd string
	var bpf string
	var dbpath string
	var listenport string
	var packetQueue int
	var persistQueue int
	var persistBatchSize int
	var persistFlushInterval time.Duration
	var alertQueue int
	var alertWorkers int
	var alertTimeout time.Duration

	flag.StringVar(&ifaces, "interface", "eth0", "Specify the network interfaces to listen on, separated by commas")
	flag.StringVar(&alertCmd, "alertcmd", "", "Specify an alert command to run when an ARP reply is captured")
	flag.StringVar(&bpf, "bpf", "", "Specify a BPF filter to use. It will be anded with the base capture filter")
	flag.StringVar(&dbpath, "dbpath", "./macs.db", "Specify the path to the database file")
	flag.StringVar(&listenport, "listenport", ":2114", "Specify the listen port for prometheus")
	flag.IntVar(&packetQueue, "packet-queue", 1024, "Size of the internal packet queue")
	flag.IntVar(&persistQueue, "persist-queue", 2048, "Size of the database persistence queue")
	flag.IntVar(&persistBatchSize, "persist-batch-size", 128, "Maximum number of updates per database transaction")
	flag.DurationVar(&persistFlushInterval, "persist-flush-interval", time.Second, "How often to flush pending database updates")
	flag.IntVar(&alertQueue, "alert-queue", 512, "Size of the alert worker queue")
	flag.IntVar(&alertWorkers, "alert-workers", 4, "Number of concurrent alert workers")
	flag.DurationVar(&alertTimeout, "alert-timeout", 10*time.Second, "Maximum duration for an alert command before it is terminated")
	promisc := flag.Bool("promisc", false, "Enable promiscuous mode")
	checkNDP := flag.Bool("ndp", false, "Check for IPv6 NDP packets")
	flag.Parse()

	interfaceList := strings.Split(ifaces, ",")

	log.Printf("Starting up on interfaces %v\n", interfaceList)
	log.Printf("Alert command: %s\n", alertCmd)
	log.Printf("Setting up db at %s\n", dbpath)
	log.Printf("BPF filter: %s\n", bpf)
	log.Printf("Promiscuous mode: %t\n", *promisc)
	log.Printf("Listen on: %s\n", listenport)
	log.Printf("Packet queue size: %d\n", packetQueue)
	log.Printf("DB queue size: %d\n", persistQueue)
	log.Printf("DB batch size: %d\n", persistBatchSize)
	log.Printf("DB flush interval: %s\n", persistFlushInterval)
	log.Printf("Alert queue size: %d\n", alertQueue)
	log.Printf("Alert worker count: %d\n", alertWorkers)
	log.Printf("Alert timeout: %s\n", alertTimeout)

	if packetQueue < 1 {
		packetQueue = 1
	}
	if persistQueue < 1 {
		persistQueue = 1
	}
	if persistBatchSize < 1 {
		persistBatchSize = 1
	}
	if alertQueue < 1 {
		alertQueue = 1
	}
	if alertWorkers < 1 {
		alertWorkers = 1
	}

	db, err := setupDB(dbpath)
	if err != nil {
		log.Fatal(err)
	}
	defer func(db *bbolt.DB) {
		err := db.Close()
		if err != nil {
			log.Printf("Error closing db: %v\n", err)
		}
	}(db)

	log.Printf("Loading all MACs from db\n")
	MacMap, err := loadAll(db)
	if err != nil {
		log.Fatal(err)
	}

	packetChannel := make(chan Reply, packetQueue)
	replyChannel := make(chan Reply, persistQueue)

	var alertChannel chan alertEvent
	if alertCmd != "" {
		alertChannel = make(chan alertEvent, alertQueue)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, localhost, _ := net.ParseCIDR("127.0.0.0/8")
	_, ipv6localhost, _ := net.ParseCIDR("::1/128")

	var workerWG sync.WaitGroup
	workerWG.Add(1)
	go func() {
		defer workerWG.Done()
		servePrometheus(ctx, listenport)
	}()

	workerWG.Add(1)
	go func() {
		defer workerWG.Done()
		saveAll(db, replyChannel, persistBatchSize, persistFlushInterval)
	}()

	if alertChannel != nil {
		for i := 0; i < alertWorkers; i++ {
			workerWG.Add(1)
			go alertWorker(ctx, &workerWG, alertCmd, alertTimeout, alertChannel)
		}
	}

	var captureWG sync.WaitGroup
	for _, iface := range interfaceList {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		pcapIface, err := setupPcap(iface, *promisc, bpf, *checkNDP)
		if err != nil {
			log.Fatalf("Error setting up pcap on interface %s: %v\n", iface, err)
		}
		captureWG.Add(1)
		go func(pi pcapInterface) {
			defer captureWG.Done()
			capturePackets(ctx, pi, packetChannel, *checkNDP)
		}(*pcapIface)
	}

	go func() {
		captureWG.Wait()
		close(packetChannel)
	}()

	shuttingDown := false
	for {
		if shuttingDown {
			reply, ok := <-packetChannel
			if !ok {
				break
			}
			if localhost.Contains(reply.Ip) || ipv6localhost.Contains(reply.Ip) || reply.Ip.String() == "::" {
				continue
			}

			if reply.IPVer == 6 {
				ndpReplies.Inc()
			} else if reply.IPVer == 4 {
				arpReplies.Inc()
			}

			status, old := checkMac(reply, MacMap)

			if status != 0 {
				if status == 1 || status == 2 {
					enqueueReply(replyChannel, reply)
				}
				if alertChannel != nil {
					event := alertEvent{
						status: status,
						reply:  reply,
						old:    old,
					}
					if !enqueueAlert(alertChannel, event) {
						alertQueueDrops.Inc()
						log.Printf("Dropping alert for %s: queue full\n", reply.Ip.String())
					}
				}
			}
			continue
		}

		select {
		case <-ctx.Done():
			log.Printf("Shutdown signal received; stopping packet capture and draining queues before exit (additional Ctrl-C ignored)\n")
			shuttingDown = true
		case reply, ok := <-packetChannel:
			if !ok {
				shuttingDown = true
				break
			}
			if localhost.Contains(reply.Ip) || ipv6localhost.Contains(reply.Ip) || reply.Ip.String() == "::" {
				continue
			}

			if reply.IPVer == 6 {
				ndpReplies.Inc()
			} else if reply.IPVer == 4 {
				arpReplies.Inc()
			}

			status, old := checkMac(reply, MacMap)

			if status != 0 {
				if status == 1 || status == 2 {
					enqueueReply(replyChannel, reply)
				}
				if alertChannel != nil {
					event := alertEvent{
						status: status,
						reply:  reply,
						old:    old,
					}
					if !enqueueAlert(alertChannel, event) {
						alertQueueDrops.Inc()
						log.Printf("Dropping alert for %s: queue full\n", reply.Ip.String())
					}
				}
			}
		}
	}

	log.Printf("Queue drain complete, finishing shutdown\n")
	stop()

	close(replyChannel)
	if alertChannel != nil {
		close(alertChannel)
	}

	captureWG.Wait()
	workerWG.Wait()
}
