package main

import (
	"fmt"
	"net"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ArpReply struct {
	Mac      net.HardwareAddr
	EtherMac net.HardwareAddr
	Ip       net.IP
	Iface    string
}

type pcapInterface struct {
	iface   string
	handle  *pcap.Handle
}

func setupPcap(iface string, promisc bool, bpf string) (*pcapInterface, error) {
	handle, err := pcap.OpenLive(iface, 1600, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if bpf != "" {
		bpf = fmt.Sprintf("(arp or rarp) and not vlan and %s", bpf)
	} else {
		bpf = "(arp or rarp) and not vlan"
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		return nil, err
	}

	return &pcapInterface{iface: iface, handle: handle}, nil
}

func capture(pcapInterface pcapInterface, packetChannel chan ArpReply) {
	handle := pcapInterface.handle
	iface := pcapInterface.iface
	defer handle.Close()
	log.Printf("beginning capture on %s\n",iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetlayer := packet.Layer(layers.LayerTypeEthernet)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == 2 { // ARP reply
				ethermac := net.HardwareAddr(ethernetlayer.(*layers.Ethernet).SrcMAC)
				mac := net.HardwareAddr(arp.SourceHwAddress)
				ip := net.IP(arp.SourceProtAddress)
				packetChannel <- ArpReply{Mac: mac, Ip: ip, EtherMac: ethermac, Iface: iface}
			}
		}
	}
}
