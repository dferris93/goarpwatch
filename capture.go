package main

import (
	"fmt"
	"net"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Reply struct {
	Mac      net.HardwareAddr
	EtherMac net.HardwareAddr
	Ip       net.IP
	Iface    string
	IPVer    int
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
		bpf = fmt.Sprintf("(arp or rarp or (icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136))) and not vlan and %s", bpf)
	} else {
		bpf = "(arp or rarp or (icmp6 and (ip6[40] == 133 or ip6[40] == 134 or ip6[40] == 135 or ip6[40] == 136))) and not vlan"
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		return nil, err
	}

	return &pcapInterface{iface: iface, handle: handle}, nil
}

func capture(pcapInterface pcapInterface, packetChannel chan Reply) {
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
				packetChannel <- Reply{Mac: mac, Ip: ip, EtherMac: ethermac, Iface: iface, IPVer: 4}
			}
		}
	}
}

func captureNdp(pcapInterface pcapInterface, ndpChannel chan Reply) {
	handle := pcapInterface.handle
	iface := pcapInterface.iface
	defer handle.Close()
	log.Printf("beginning NDP capture on %s\n", iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
			if icmpv6Layer != nil {
				icmpv6 := icmpv6Layer.(*layers.ICMPv6)
				if icmpv6.TypeCode.Type() == layers.ICMPv6TypeNeighborAdvertisement || 
				icmpv6.TypeCode.Type() == layers.ICMPv6TypeNeighborSolicitation ||
				icmpv6.TypeCode.Type() == layers.ICMPv6TypeRouterAdvertisement || 
				icmpv6.TypeCode.Type() == layers.ICMPv6TypeRouterSolicitation {
					ethermac := net.HardwareAddr(ethernetLayer.(*layers.Ethernet).SrcMAC)
					ip := ipv6Layer.(*layers.IPv6).SrcIP
					// ndp is much simpler than arp.  There is no mac embedded in an NDP packet
					// ndp sends the solicitation to a multicast address and the reply is sent to the solicitor's unicast address
					ndpChannel <- Reply{Mac: ethermac, Ip: ip, EtherMac: ethermac, Iface: iface, IPVer: 6}
				} 
			}
		}
	}
}