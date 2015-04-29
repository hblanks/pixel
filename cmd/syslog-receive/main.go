package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s\n", os.Args[0])
	fmt.Fprintf(os.Stderr,
		"Binds to a UDP port and prints syslog messages to stdout.\n"+
			"Relevant environment variables (and defaults):\n"+
			"\n"+
			"    LISTEN_ADDRESS=:5140\n\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func syslogReceive() error {
	messageBuf := make([]byte, pixel.UDPMaxBytes)

	listenAddress := os.Getenv("LISTEN_ADDRESS")
	if len(listenAddress) == 0 {
		listenAddress = "127.0.0.1:5140"
	}

	addr, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		numBytes, _, err := conn.ReadFromUDP(messageBuf)
		if err != nil {
			log.Printf("v\n", err)
		}
		fmt.Printf("%s\n", messageBuf[:numBytes])
	}
}

func main() {
	help := flag.Bool("h", false, "Print help")
	flag.Parse()

	if *help || flag.NArg() != 0 {
		usage()
	}

	err := syslogReceive()
	if err != nil {
		log.Printf("%v\n", err)
		os.Exit(1)
	}
}
