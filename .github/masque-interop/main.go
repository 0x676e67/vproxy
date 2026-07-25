package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	mode := flag.String("mode", "", "client or echo")
	addr := flag.String("addr", "127.0.0.1:4434", "UDP echo listen address")
	proxy := flag.String("proxy", "", "MASQUE proxy URI template")
	target := flag.String("target", "", "UDP target address")
	cert := flag.String("cert", "", "trusted proxy certificate")
	flag.Parse()

	switch *mode {
	case "client":
		runClient(*proxy, *target, *cert)
	case "echo":
		runEcho(*addr)
	default:
		log.Fatal("-mode must be client or echo")
	}
}

func runClient(proxy, target, certFile string) {
	if proxy == "" || target == "" || certFile == "" {
		log.Fatal("-proxy, -target and -cert are required in client mode")
	}
	cert, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		log.Fatal("failed to load proxy certificate")
	}
	template, err := uritemplate.New(proxy)
	if err != nil {
		log.Fatal(err)
	}
	request, err := masque.NewRequest(context.Background(), template, target)
	if err != nil {
		log.Fatal(err)
	}
	transport := masque.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{http3.NextProtoH3},
			RootCAs:    roots,
			ServerName: "localhost",
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	connection, _, err := transport.Dial(request)
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}
	payload := []byte("vproxy-masque-interop-ok")
	if _, err := connection.WriteTo(payload, nil); err != nil {
		log.Fatal(err)
	}
	response := make([]byte, 1500)
	length, _, err := connection.ReadFrom(response)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(response[:length], payload) {
		log.Fatalf("unexpected response: %q", response[:length])
	}
	log.Printf("received %q through CONNECT-UDP", response[:length])
}

func runEcho(addr string) {
	connection, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	log.Printf("UDP echo listening on %s", connection.LocalAddr())
	buffer := make([]byte, 1500)
	for {
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := connection.WriteTo(buffer[:length], peer); err != nil {
			log.Fatal(err)
		}
	}
}
