package main

import (
	"net"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func setupPcap(iface string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, err
	}

	return handle, nil
}

func capture(handle *pcap.Handle, packetChannel chan ArpReply) {
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        arpLayer := packet.Layer(layers.LayerTypeARP)
        if arpLayer != nil {
            arp := arpLayer.(*layers.ARP)
            if arp.Operation == 2 { // ARP reply
				mac := net.HardwareAddr(arp.SourceHwAddress)
                ip := net.IP(arp.SourceProtAddress)
				packetChannel <- ArpReply{Mac: mac, Ip: ip}
            }
        }
    }
}
