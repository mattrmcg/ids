package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mattrmcg/ids/internal/capture"
	"github.com/mattrmcg/ids/internal/detect"
)

func main() {

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan bool, 1)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println("Received signal:", sig)

		fmt.Println("Canceling packet event stream...")
		cancel()

		done <- true
	}()

	logging := flag.Bool("l", false, "Enable verbose logging")

	flag.Parse()

	handle, err := capture.OpenLiveHandle("en0", capture.Options{Immediate: true, IncomingTrafficOnly: true})
	if err != nil {
		log.Fatal(err)
	}
	defer capture.CloseHandle(handle)

	out, err := capture.Stream(ctx, handle)
	if err != nil {
		log.Fatal(err)
	}

	sd := detect.CreateScanDetector()
	defer sd.Stop()

	for ev := range out {
		sd.DetectPortscan(ev)

		if *logging {
			fmt.Println(ev)
		}
	}

	<-done
	fmt.Println("Exiting....")
}
