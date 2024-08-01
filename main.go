package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os/exec"
	"strings"
)

func checkMac(Reply Reply, MacMap map[string]string) (int, string) {
	macString := strings.TrimSpace(Reply.Mac.String())
	etherMacString := strings.TrimSpace(Reply.EtherMac.String())
	ipString := strings.TrimSpace(Reply.Ip.String())

	if _, ok := MacMap[ipString]; !ok {
		MacMap[ipString] = macString
		macNew.Inc()
		log.Printf("First time seeing %s at %s\n", ipString, macString)
		return 1, ""
	} else if MacMap[ipString] != macString {
		log.Printf("ALERT! %s has a new MAC address: %s (was %s)\n", ipString, macString, MacMap[ipString])
		MacMap[ipString] = macString
		macChanges.Inc()
		return 2, MacMap[ipString]
	} else if macString != etherMacString {
		log.Printf("ALERT! ARP MAC address does not match Ethernet MAC address %s %s %s\n", ipString, macString, etherMacString)
		macMismatches.Inc()
		return 3, ""
	}

	return 0, ""
}

func runAlert(alertCmd string, status int, reply Reply, old string) error {
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
	err := cmd.Run()
	if err != nil {
		stderr := cmd.Stderr.(*bytes.Buffer).String()
		log.Printf("Error running alert command: %s\n", err)
		log.Printf("%s\n", stderr)
		return err
	}
	log.Printf("Alert command ran successfully\n")
	stdout := cmd.Stdout.(*bytes.Buffer).String()
	log.Printf("%s\n", stdout)
	return nil
}

func main() {
	var ifaces string
	var alertCmd string
	var bpf string
	var dbpath string

	// Define flags
	flag.StringVar(&ifaces, "interface", "eth0", "Specify the network interfaces to listen on, separated by commas")
	flag.StringVar(&alertCmd, "alertcmd", "", "Specify an alert command to run when an ARP reply is captured")
	flag.StringVar(&bpf, "bpf", "", "Specify a BPF filter to use. It will be anded with 'arp'")
	flag.StringVar(&dbpath, "dbpath", "./macs.db", "Specify the path to the database file")
	promisc := flag.Bool("promisc", false, "Enable promiscuous mode")
	checkNDP := flag.Bool("ndp", false, "Check for IPv6 NDP packets")
	flag.Parse()

	interfaceList := strings.Split(ifaces, ",")

	log.Printf("Starting up on interfaces %v\n", interfaceList)
	log.Printf("Alert command: %s\n", alertCmd)
	log.Printf("Setting up db at %s\n", dbpath)
	log.Printf("BPF filter: %s\n", bpf)
	log.Printf("Promiscuous mode: %t\n", *promisc)
	db, err := setupDB(dbpath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	log.Printf("Loading all MACs from db\n")
	MacMap, err := loadAll(db)
	if err != nil {
		log.Fatal(err)
	}

	packetChannel := make(chan Reply)
	replyChannel := make(chan Reply)

	_, localhost, _ := net.ParseCIDR("127.0.0.0/8")

	go servePrometheus()
	go saveAll(db, replyChannel)

	for _, iface := range interfaceList {
		pcapInterface, err := setupPcap(iface, *promisc, bpf)
		if err != nil {
			log.Fatalf("Error setting up pcap on interface %s: %v\n", iface, err)
		}
		go capture(*pcapInterface, packetChannel)
		if *checkNDP {
			go captureNdp(*pcapInterface, packetChannel)
		}
	}

	for reply := range packetChannel {
		if localhost.Contains(reply.Ip) {
			continue
		}

		if reply.IPVer == 6 {
			ndpReplies.Inc()
		} else if reply.IPVer != 4 {
			arpReplies.Inc()
		}

		status, old := checkMac(reply, MacMap)
		if status != 0 {
			replyChannel <- reply
			if alertCmd != "" {
				err := runAlert(alertCmd, status, reply, old)
				if err != nil {
					log.Printf("Error running alert command: %s\n", err)
				}
			}
		}
	}
}