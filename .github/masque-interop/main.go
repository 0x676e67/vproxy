package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
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
	authStdin := flag.Bool("auth-stdin", false, "read one managed proxy credential JSON from stdin; never pass secrets in flags")
	flag.Parse()

	switch *mode {
	case "client":
		var credentials io.Reader
		if *authStdin {
			credentials = os.Stdin
		}
		if err := runClient(*proxy, *target, *cert, credentials); err != nil {
			log.Fatal(err)
		}
	case "echo":
		runEcho(*addr)
	default:
		log.Fatal("-mode must be client or echo")
	}
}

type proxyCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Keep credentials out of argv, URI userinfo and parser diagnostics. This
// interop helper accepts only the managed credential format used by vproxy.
func readCredential(input io.Reader) (proxyCredential, error) {
	invalid := errors.New("invalid managed proxy credential input")
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(raw) > 4096 {
		return proxyCredential{}, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return proxyCredential{}, invalid
	}
	var credential proxyCredential
	seen := make(map[string]bool, 2)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return proxyCredential{}, invalid
		}
		name, ok := key.(string)
		if !ok || seen[name] || (name != "username" && name != "password") {
			return proxyCredential{}, invalid
		}
		seen[name] = true
		value := &credential.Username
		if name == "password" {
			value = &credential.Password
		}
		if err := decoder.Decode(value); err != nil {
			return proxyCredential{}, invalid
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != 2 {
		return proxyCredential{}, invalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return proxyCredential{}, invalid
	}
	login, err := hex.DecodeString(strings.TrimPrefix(credential.Username, "vp2_"))
	if err != nil || len(login) != 16 || credential.Username != "vp2_"+hex.EncodeToString(login) {
		return proxyCredential{}, invalid
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(credential.Password)
	if err != nil || len(secret) != 32 || credential.Password != base64.RawURLEncoding.EncodeToString(secret) {
		return proxyCredential{}, invalid
	}
	return credential, nil
}

func proxyServerName(proxy string) (string, error) {
	parsed, err := url.Parse(proxy)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return "", errors.New("proxy template requires an HTTPS host without userinfo")
	}
	return parsed.Hostname(), nil
}

func runClient(proxy, target, certFile string, credentials io.Reader) error {
	if proxy == "" || target == "" || certFile == "" {
		return errors.New("-proxy, -target and -cert are required in client mode")
	}
	serverName, err := proxyServerName(proxy)
	if err != nil {
		return err
	}
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		return errors.New("failed to load proxy certificate")
	}
	template, err := uritemplate.New(proxy)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := masque.NewRequest(ctx, template, target)
	if err != nil {
		return err
	}
	if credentials != nil {
		credential, err := readCredential(credentials)
		if err != nil {
			return err
		}
		request.Header().Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(credential.Username+":"+credential.Password)))
	}
	transport := masque.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{http3.NextProtoH3},
			RootCAs:    roots,
			ServerName: serverName,
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}
	connection, handshake, err := transport.Dial(request)
	if handshake != nil {
		log.Printf("CONNECT-UDP status=%d challenge=%t", handshake.StatusCode, handshake.Header.Get("Proxy-Authenticate") != "")
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	payload := []byte("vproxy-masque-interop-ok")
	if _, err := connection.WriteTo(payload, nil); err != nil {
		return err
	}
	response := make([]byte, 1500)
	length, _, err := connection.ReadFrom(response)
	if err != nil {
		return err
	}
	if !bytes.Equal(response[:length], payload) {
		return fmt.Errorf("unexpected UDP response length %d", length)
	}
	log.Printf("received %q through CONNECT-UDP", response[:length])
	return nil
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
