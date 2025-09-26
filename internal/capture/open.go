package capture

import (
	"github.com/google/gopacket/pcap"
)

type Options struct {
	Immediate           bool // immediate mode
	IncomingTrafficOnly bool // traffic direction
}

// Open live libpcap handle
func OpenLiveHandle(iface string, opt Options) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	if opt.Immediate {
		if err := inactive.SetImmediateMode(true); err != nil {
			return nil, err
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, err
	}

	if opt.IncomingTrafficOnly {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, err
		}
	}

	return handle, nil
}

func CloseHandle(handle *pcap.Handle) {
	handle.Close()
}
