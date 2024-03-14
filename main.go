package main

import (
    "bytes"
	"flag"
	"log"
	"net"
    "os/exec"
)

type ArpReply struct {
	Mac net.HardwareAddr
	Ip  net.IP
}

func checkMac(mac net.HardwareAddr, ip net.IP, MacMap map[string]string) int {
    if _, ok := MacMap[ip.String()]; !ok {
        MacMap[ip.String()] = mac.String()
        log.Printf("First time seeing %s at %s\n", ip, mac)
        return 1
    } else if MacMap[ip.String()] != mac.String() {
        log.Printf("ALERT! %s has a new MAC address: %s (was %s)\n", ip, mac, MacMap[ip.String()])
        MacMap[ip.String()] = mac.String()
        return 2
    }
    return 0
}

func runAlert(alertCmd string, status int, reply ArpReply) error {
    var args []string
    if status == 1 {
        args = []string{"new", reply.Ip.String(), reply.Mac.String()}
    } else if status == 2 {
        args = []string{"changed", reply.Ip.String(), reply.Mac.String()}
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
    var MacMap = make(map[string]string)

	// Define flags
	flag.StringVar(&iface, "interface", "eth0", "Specify the network interface to listen on")
	flag.StringVar(&alertCmd, "alertcmd", "", "Specify an alert command to run when an ARP reply is captured")
	flag.Parse()

	packetChannel := make(chan ArpReply)

	pcapHandle, err := setupPcap(iface)
	if err != nil {
		log.Fatal(err)
	}

	go capture(pcapHandle, packetChannel)
	for {
		arpReply := <-packetChannel
		log.Printf("ARP reply from %s with MAC %s\n", arpReply.Ip, arpReply.Mac)
        status := checkMac(arpReply.Mac, arpReply.Ip, MacMap)
        if status == 1 || status == 2 {
            if alertCmd != "" {
                err := runAlert(alertCmd, status, arpReply)
                if err != nil {
                    log.Printf("Error running alert command: %s\n", err)
                }
            }
        }
	}
}