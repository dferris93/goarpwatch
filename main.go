package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os/exec"
	"strings"
)

type ArpReply struct {
	Mac net.HardwareAddr
	Ip  net.IP
}

func checkMac(mac net.HardwareAddr, ip net.IP, MacMap map[string]string) (int, string) {
    macString := strings.TrimSpace(mac.String())
    ipString := strings.TrimSpace(ip.String())
    if macString == "00:00:00:00:00:00" {
        return 0, ""
    } else if macString == "ff:ff:ff:ff:ff:ff" {
        return 0, ""
    }

    if _, ok := MacMap[ipString]; !ok {
        MacMap[ipString] = macString
        log.Printf("First time seeing %s at %s\n", ip, mac)
        return 1, ""
    } else if MacMap[ipString] != macString {
        log.Printf("ALERT! %s has a new MAC address: %s (was %s)\n", ipString, macString, MacMap[ipString])
        MacMap[ipString] = macString
        return 2, MacMap[ipString]
    }
    return 0, ""
}

func runAlert(alertCmd string, status int, reply ArpReply, old string) error {
    var args []string
    if status == 1 {
        args = []string{"new", reply.Ip.String(), reply.Mac.String()}
    } else if status == 2 {
        args = []string{"changed", reply.Ip.String(), reply.Mac.String(), old}
    } else if status == 3 {
        args = []string{"ip_changed", reply.Ip.String(), reply.Mac.String(), old}
    }
    cmd := exec.Command(alertCmd, args...)
    cmd.Stderr = &bytes.Buffer{}
    cmd.Stdout = &bytes.Buffer{}
    err := cmd.Run()
    if err != nil {
        stderr := cmd.Stderr.(*bytes.Buffer).String()
        log.Printf("Error running alert command: %s\n", err)
        log.Printf("%s\n",stderr)
        return err
    }
    log.Printf("Alert command ran successfully\n")
    stdout := cmd.Stdout.(*bytes.Buffer).String()
    log.Printf("%s\n", stdout)
    return nil
}

func main() {
	var iface string
	var alertCmd string
    var bpf string
    var dbpath string

	// Define flags
	flag.StringVar(&iface, "interface", "eth0", "Specify the network interface to listen on")
	flag.StringVar(&alertCmd, "alertcmd", "", "Specify an alert command to run when an ARP reply is captured")
    flag.StringVar(&bpf, "bpf", "", "Specify a BPF filter to use.  It will be anded with 'arp'")
    flag.StringVar(&dbpath, "dbpath", "./macs.db", "Specify the path to the database file")
	flag.Parse()


    log.Printf("Starting up on interface %s\n", iface)
    log.Printf("Alert command: %s\n", alertCmd)
    log.Printf("Setting up db at %s\n", dbpath)
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

	packetChannel := make(chan ArpReply)
    replyChannel := make(chan ArpReply)

	pcapHandle, err := setupPcap(iface, bpf)
	if err != nil {
		log.Fatal(err)
	}

    _, localhost, _ := net.ParseCIDR("127.0.0.0/8")

	go capture(pcapHandle, packetChannel)
    go saveAll(db, replyChannel)

	for {
		arpReply := <-packetChannel
        if localhost.Contains(arpReply.Ip) {
            continue
        }
        status, old := checkMac(arpReply.Mac, arpReply.Ip, MacMap)
        if status != 0 {
            replyChannel <- arpReply
            if alertCmd != "" {
                err := runAlert(alertCmd, status, arpReply, old)
                if err != nil {
                    log.Printf("Error running alert command: %s\n", err)
                }
            }
        }
	}
}