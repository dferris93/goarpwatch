package main

import (
	"fmt"
	"log"
	"net"

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
	iface  string
	handle *pcap.Handle
}

func setupPcap(iface string, promisc bool, bpf string, enableNDP bool) (*pcapInterface, error) {
	handle, err := pcap.OpenLive(iface, 1600, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	baseFilter := "arp or rarp"
	if enableNDP {
		baseFilter = fmt.Sprintf("%s or icmp6", baseFilter)
	}

	if bpf != "" {
		bpf = fmt.Sprintf("(%s) and not vlan and (%s)", baseFilter, bpf)
	} else {
		bpf = fmt.Sprintf("(%s) and not vlan", baseFilter)
	}
	if err := handle.SetBPFFilter(bpf); err != nil {
		return nil, err
	}

	return &pcapInterface{iface: iface, handle: handle}, nil
}

func capturePackets(pcapInterface pcapInterface, packetChannel chan Reply, enableNDP bool) {
	handle := pcapInterface.handle
	iface := pcapInterface.iface
	defer handle.Close()
	log.Printf("beginning capture on %s\n", iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetlayer := packet.Layer(layers.LayerTypeEthernet)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == 2 { // ARP reply
				if ethernetlayer == nil {
					continue
				}
				ethermac := net.HardwareAddr(ethernetlayer.(*layers.Ethernet).SrcMAC)
				mac := net.HardwareAddr(arp.SourceHwAddress)
				ip := net.IP(arp.SourceProtAddress)
				packetChannel <- Reply{Mac: mac, Ip: ip, EtherMac: ethermac, Iface: iface, IPVer: 4}
			}
		}
		if !enableNDP {
			continue
		}
		reply, ok := ndpPacketToReply(packet, iface)
		if ok {
			packetChannel <- reply
		}
	}
}

func ndpPacketToReply(packet gopacket.Packet, iface string) (Reply, bool) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if ethernetLayer == nil || ipv6Layer == nil || icmpv6Layer == nil {
		return Reply{}, false
	}

	eth := ethernetLayer.(*layers.Ethernet)
	ipv6 := ipv6Layer.(*layers.IPv6)
	icmpv6 := icmpv6Layer.(*layers.ICMPv6)
	icmpType := icmpv6.TypeCode.Type()
	if icmpType != layers.ICMPv6TypeNeighborAdvertisement &&
		icmpType != layers.ICMPv6TypeNeighborSolicitation &&
		icmpType != layers.ICMPv6TypeRouterAdvertisement &&
		icmpType != layers.ICMPv6TypeRouterSolicitation {
		return Reply{}, false
	}

	ip := ipv6.SrcIP
	mac := net.HardwareAddr(eth.SrcMAC)

	switch icmpType {
	case layers.ICMPv6TypeNeighborSolicitation:
		if nsLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); nsLayer != nil {
			ns := nsLayer.(*layers.ICMPv6NeighborSolicitation)
			if optMac, ok := ndpOptionMAC(ns.Options, layers.ICMPv6OptSourceAddress); ok {
				mac = optMac
			}
		}
	case layers.ICMPv6TypeNeighborAdvertisement:
		if naLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); naLayer != nil {
			na := naLayer.(*layers.ICMPv6NeighborAdvertisement)
			if na.TargetAddress != nil && !na.TargetAddress.IsUnspecified() {
				ip = na.TargetAddress
			}
			if optMac, ok := ndpOptionMAC(na.Options, layers.ICMPv6OptTargetAddress); ok {
				mac = optMac
			}
		}
	case layers.ICMPv6TypeRouterSolicitation:
		if rsLayer := packet.Layer(layers.LayerTypeICMPv6RouterSolicitation); rsLayer != nil {
			rs := rsLayer.(*layers.ICMPv6RouterSolicitation)
			if optMac, ok := ndpOptionMAC(rs.Options, layers.ICMPv6OptSourceAddress); ok {
				mac = optMac
			}
		}
	case layers.ICMPv6TypeRouterAdvertisement:
		if raLayer := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement); raLayer != nil {
			ra := raLayer.(*layers.ICMPv6RouterAdvertisement)
			if optMac, ok := ndpOptionMAC(ra.Options, layers.ICMPv6OptSourceAddress); ok {
				mac = optMac
			}
		}
	}

	if ip == nil || ip.IsUnspecified() {
		return Reply{}, false
	}

	return Reply{Mac: mac, Ip: ip, EtherMac: net.HardwareAddr(eth.SrcMAC), Iface: iface, IPVer: 6}, true
}

func ndpOptionMAC(options []layers.ICMPv6Option, optType layers.ICMPv6Opt) (net.HardwareAddr, bool) {
	for _, opt := range options {
		if opt.Type != optType {
			continue
		}
		if len(opt.Data) < 6 {
			continue
		}
		return net.HardwareAddr(opt.Data[:6]), true
	}
	return nil, false
}
