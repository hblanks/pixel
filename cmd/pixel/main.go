package main

import (
	"flag"
	"fmt"
	"github.com/hblanks/pixel"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func usage() {
	fmt.Fprintf(os.Stderr,
		"Usage: %s\n", os.Args[0])
	fmt.Fprintf(os.Stderr,
		"Serves analytics HTTP requests; logs to syslog by UDP.\n"+
			"Relevant environment variables (and defaults):\n"+
			"\n"+
			"    LISTEN_ADDRESS=:8080\n"+
			"    SYSLOG_ADDRESS=localhost:514\n"+
			"    SYSLOG_FACILITY=LOG_LOCAL0\n"+
			"    SYSLOG_LEVEL=LOG_INFO\n\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func start() error {
	listenAddress := os.Getenv("LISTEN_ADDRESS")
	if len(listenAddress) == 0 {
		listenAddress = ":8080"
	}

	syslogAddress := os.Getenv("SYSLOG_ADDRESS")
	if len(syslogAddress) == 0 {
		syslogAddress = "localhost:514"
	}

	syslogPriority := pixel.NewSyslogPriority(os.Getenv("SYSLOG_LEVEL"),
		os.Getenv("SYSLOG_FACILITY"))

	server, err := pixel.NewServer(syslogAddress, syslogPriority)
	if err != nil {
		return err
	}
	log.Printf("start listen=%s syslog=%s priority=%d\n",
		listenAddress, syslogAddress, syslogPriority)
	go server.ListenAndServe(listenAddress)

	sigChannel := make(chan os.Signal)
	signal.Notify(sigChannel, syscall.SIGINT, syscall.SIGTERM)
	log.Println(<-sigChannel)

	return nil
}

func main() {
	help := flag.Bool("h", false, "Print help")
	flag.Parse()

	if *help || flag.NArg() != 0 {
		usage()
	}

	err := start()
	if err != nil {
		log.Printf("%v\n", err)
		os.Exit(1)
	}
}
