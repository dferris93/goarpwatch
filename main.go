package main

import (
	"bytes"
	"flag"
	"go.etcd.io/bbolt"
	"log"
	"net"
	"os/exec"
	"strings"
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

func runAlert(alertCmd string, status int, reply Reply, old string) {
	var args []string
	if status == 1 {
		args = []string{"new", reply.Ip.String(), reply.Mac.String(), reply.Iface}
	} else if status == 2 {
		args = []string{"changed", reply.Ip.String(), reply.Mac.String(), reply.Iface, old}
	} else if status == 3 {
		args = []string{"mismatch", reply.Ip.String(), reply.Mac.String(), reply.Iface, reply.EtherMac.String()}
	}

	cmd := exec.Command(alertCmd, args...)
	cmd.Stderr = &bytes.Buffer{}
	cmd.Stdout = &bytes.Buffer{}
	log.Printf("Running command: %s\n", cmd.Args)
	err := cmd.Run()
	stderr := cmd.Stderr.(*bytes.Buffer).String()
	stdout := cmd.Stdout.(*bytes.Buffer).String()
	if err != nil {
		log.Printf("Error running alert command: %s\n", err)
		log.Printf("stdout: %s\n", stdout)
		log.Printf("stderr: %s\n", stderr)
	}
	log.Printf("Alert command ran successfully\n")
	log.Printf("%s\n", stdout)
}

func main() {
	var ifaces string
	var alertCmd string
	var bpf string
	var dbpath string
	var listenport string

	flag.StringVar(&ifaces, "interface", "eth0", "Specify the network interfaces to listen on, separated by commas")
	flag.StringVar(&alertCmd, "alertcmd", "", "Specify an alert command to run when an ARP reply is captured")
	flag.StringVar(&bpf, "bpf", "", "Specify a BPF filter to use. It will be anded with the base capture filter")
	flag.StringVar(&dbpath, "dbpath", "./macs.db", "Specify the path to the database file")
	flag.StringVar(&listenport, "listenport", ":2114", "Specify the listen port for prometheus")
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

	db, err := setupDB(dbpath)
	if err != nil {
		log.Fatal(err)
	}
	defer func(db *bbolt.DB) {
		err := db.Close()
		if err != nil {
			log.Fatalf("Error closing db: %v\n", err)
		}
	}(db)

	log.Printf("Loading all MACs from db\n")
	MacMap, err := loadAll(db)
	if err != nil {
		log.Fatal(err)
	}

	packetChannel := make(chan Reply)
	replyChannel := make(chan Reply)

	_, localhost, _ := net.ParseCIDR("127.0.0.0/8")
	_, ipv6localhost, _ := net.ParseCIDR("::1/128")

	go servePrometheus(listenport)
	go saveAll(db, replyChannel)

	for _, iface := range interfaceList {
		pcapInterface, err := setupPcap(iface, *promisc, bpf, *checkNDP)
		if err != nil {
			log.Fatalf("Error setting up pcap on interface %s: %v\n", iface, err)
		}
		go capturePackets(*pcapInterface, packetChannel, *checkNDP)
	}

	for reply := range packetChannel {
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
				replyChannel <- reply
			}
			if alertCmd != "" {
				go runAlert(alertCmd, status, reply, old)
			}
		}
	}
}
