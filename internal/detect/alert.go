package detect

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

type Alert struct {
	TS     time.Time  `json:"ts"`
	Source netip.Addr `json:"src"`
	Type   string     `json:"type"`
}

func SendAlert(ts time.Time, source netip.Addr, alertType string) error {
	a := Alert{TS: ts, Source: source, Type: alertType}
	jsonData, err := json.Marshal(a)
	if err != nil {
		fmt.Println("Error marshaling json:", err)
		return err
	}
	fmt.Println(string(jsonData))
	return nil
}
