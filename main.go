package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strconv"
	"strings"
	"sync"
)

func main() {
	usr, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cant figure out current user: %v\n", err)
		os.Exit(2)
	}

	listenStr := os.Getenv("LISTEN")
	if listenStr == "" {
		listenStr = "127.0.0.1:443"
	}

	backendStr := os.Getenv("BACKEND")
	if backendStr == "" {
		backendStr = "127.0.0.1:80"
	}

	portIdx := strings.Index(listenStr, ":")
	if portIdx < 0 {
		fmt.Fprintf(os.Stderr, "env var LISTEN does not contain required port number\n")
		os.Exit(2)
	}

	port, portErr := strconv.ParseUint(listenStr[portIdx+1:], 10, 16)
	if portErr != nil {
		fmt.Fprintf(os.Stderr, "problem parsing port from LISTEN env var: %s\n", portErr)
		os.Exit(2)
	}

	if port < 1024 && !isRoot(usr) {
		fmt.Fprintf(os.Stderr, "tlself needs to be started with sudo if listening on port %d, a privileged port\n", port)
		os.Exit(2)
	}

	workdir := path.Join(usr.HomeDir, ".tlself")
	err = os.MkdirAll(workdir, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create hidden work dir ~/.tlself: %v\n", err)
		os.Exit(2)
	}

	certFile := path.Join(workdir, "cert.pem")
	keyFile := path.Join(workdir, "key.pem")
	root := LoadOrCreateRootCA(certFile, keyFile)

	if err := ensureSystemTrusted(usr, certFile); err != nil {
		fmt.Fprintf(os.Stderr, "unable to add cert file to trusted certificates: %v\n", err)
		os.Exit(2)
	}

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
		// Optional, for requesting certificates on the fly from Let's Encrypt
		// and stpling OCSP
		GetCertificate: root.GetCertificate,
	}

	ln, err := tls.Listen("tcp", listenStr, tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to listen on %s: %v\n", listenStr, err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "TLS proxy running: %s => %s\n", listenStr, backendStr)

	p, err := newProxy(backendStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to make proxy to %s: %v\n", backendStr, err)
		os.Exit(2)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error accepting connection: %v\n", err)
			continue
		}
		go p.proxy(conn)
	}
}

func isRoot(usr *user.User) bool {
	return usr.Uid == "0"
}

type proxy struct {
	backend *net.TCPAddr
}

func newProxy(backendStr string) (proxy, error) {
	var p proxy

	rAddr, err := net.ResolveTCPAddr("tcp", backendStr)
	if err != nil {
		return p, err
	}

	p = proxy{
		backend: rAddr,
	}
	return p, nil
}

func (p proxy) proxy(conn net.Conn) {

	defer func() {
		err := conn.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error closing frontend connection: %v\n", err)
		}
	}()

	bConn, err := net.DialTCP("tcp", nil, p.backend)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error connecting to %s: %v\n", p.backend, err)
		return
	}
	defer func() {
		err := bConn.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error closing backend connection: %v\n", err)
		}
	}()

	wg := sync.WaitGroup{}

	wg.Add(2)

	go func() {
		_, err := io.Copy(bConn, conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error sending data to backend connection: %v\n", err)
		}
		wg.Done()
	}()

	go func() {
		_, err := io.Copy(conn, bConn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error sending data to frontend connection: %v\n", err)
		}
		wg.Done()
	}()

	wg.Wait()
}

func ensureSystemTrusted(usr *user.User, certFile string) error {
	if systemTrusted(certFile) {
		return nil
	}

	var output []byte
	var cmd *exec.Cmd
	var err error

	if isRoot(usr) {
		cmd = exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certFile)
	} else {
		fmt.Fprintln(os.Stderr, "We need sudo to execute `security add-trusted-cert`. Please enter your password below.")
		cmd = exec.Command("/bin/sh", "-c", fmt.Sprintf("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s", certFile))
	}

	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", output)
		return err
	}

	fmt.Fprintln(os.Stderr, "Certificate added successfully.")
	return nil
}

func systemTrusted(certFile string) bool {
	cmd := exec.Command("security", "verify-cert", "-c", certFile)
	err := cmd.Run()
	return err == nil
}
