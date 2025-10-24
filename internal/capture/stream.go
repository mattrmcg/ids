package capture

import (
	"context"
	"time"

	"log"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mattrmcg/ids/internal/types"
)

// Streams packet events to channel
func Stream(ctx context.Context, handle *pcap.Handle) (<-chan types.Event, error) {
	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	pktCh := ps.Packets()

	out := make(chan types.Event, 4096) // buffer for backpressure
	go func() {
		defer close(out)

		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-pktCh:
				if !ok {
					log.Println("Something happened reading pkt from pkt chan. Ending goroutine...")
					return
				}

				var srcIP, dstIP netip.Addr
				var proto uint8
				if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
					ip := l.(*layers.IPv4)
					proto = uint8(ip.Protocol)
					if addr, ok := netip.AddrFromSlice(ip.SrcIP); ok {
						srcIP = addr
					}
					if addr, ok := netip.AddrFromSlice(ip.DstIP); ok {
						dstIP = addr
					}

				} else if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
					ip := l.(*layers.IPv6)
					proto = uint8(ip.NextHeader)
					if addr, ok := netip.AddrFromSlice(ip.SrcIP); ok {
						srcIP = addr
					}
					if addr, ok := netip.AddrFromSlice(ip.DstIP); ok {
						dstIP = addr
					}
				} else {
					continue
				}

				var dport uint16
				var isSYN, isACK bool
				if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
					tcp := l.(*layers.TCP)
					dport = uint16(l.(*layers.TCP).DstPort)
					isSYN = tcp.SYN
					isACK = tcp.ACK
				} else if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
					dport = uint16(l.(*layers.UDP).DstPort)
				} else {
					continue
				}

				currTime := time.Now()

				ev := types.Event{TS: currTime, SrcIP: srcIP, DstIP: dstIP, DstPort: dport, Proto: proto, SYN: isSYN, ACK: isACK}

				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}

			}
		}
	}()

	return out, nil
}
