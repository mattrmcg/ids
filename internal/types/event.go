package types

import (
	"net/netip"
	"time"
)

type Proto uint8

const (
	ProtoTCP Proto = 6
	ProtoUDP Proto = 17
)

type Event struct {
	TS      time.Time
	SrcIP   netip.Addr
	DstIP   netip.Addr
	DstPort uint16
	Proto   uint8
	SYN     bool
	ACK     bool
}
