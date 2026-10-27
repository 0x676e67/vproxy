package main

import (
	"errors"
	"strings"
	"testing"
)

func TestProxyServerName(t *testing.T) {
	for proxy, expected := range map[string]string{
		"https://localhost:4433/.well-known/masque/udp/{target_host}/{target_port}/": "localhost",
		"https://127.0.0.1:4433/.well-known/masque/udp/{target_host}/{target_port}/": "127.0.0.1",
		"https://[::1]:4433/.well-known/masque/udp/{target_host}/{target_port}/":     "::1",
	} {
		actual, err := proxyServerName(proxy)
		if err != nil || actual != expected {
			t.Fatalf("proxy TLS name: got %q, %v; want %q", actual, err, expected)
		}
	}
	for _, proxy := range []string{"", "http://localhost:4433/", "https:///missing-host", "https://user:private@localhost:4433/"} {
		if _, err := proxyServerName(proxy); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe proxy template was accepted or exposed its userinfo")
		}
	}
}

func TestCredentialInput(t *testing.T) {
	login, password := "vp2_"+strings.Repeat("0", 32), strings.Repeat("A", 43)
	valid := `{"username":"` + login + `","password":"` + password + `"}`
	credential, err := readCredential(strings.NewReader(valid + "\n"))
	if err != nil || credential.Username != login || credential.Password != password {
		t.Fatal("valid managed credential was rejected")
	}
	for _, input := range []string{
		valid + `{}`, valid + "garbage", valid + strings.Repeat(" ", 4096),
		strings.Replace(valid, `"password":`, `"extra":0,"password":`, 1),
		strings.Replace(valid, `"password":`, `"password":"wrong","password":`, 1),
		strings.Replace(valid, login, "other_"+strings.Repeat("0", 32), 1),
		strings.Replace(valid, password, strings.Repeat("A", 42)+"B", 1), // Noncanonical base64 padding bits.
		strings.Replace(valid, password, "", 1),
		`null`, `[]`, `{"username":null,"password":"` + password + `"}`,
	} {
		if _, err := readCredential(strings.NewReader(input)); err == nil || err.Error() != "invalid managed proxy credential input" {
			t.Fatal("invalid credential input was accepted or produced variable diagnostics")
		}
	}
	if _, err := readCredential(failingReader{}); err == nil || err.Error() != "invalid managed proxy credential input" {
		t.Fatal("input read error exposed its original diagnostic")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("private diagnostic") }

type countingReader struct{ read int }

func (reader *countingReader) Read(buffer []byte) (int, error) {
	for i := range buffer {
		buffer[i] = ' '
	}
	reader.read += len(buffer)
	return len(buffer), nil
}

func TestCredentialInputReadBound(t *testing.T) {
	reader := &countingReader{}
	if _, err := readCredential(reader); err == nil || reader.read != 4097 {
		t.Fatal("credential reader exceeded or did not enforce its input bound")
	}
}
