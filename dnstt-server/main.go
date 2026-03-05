// dnstt-server is the server end of a DNS tunnel.
//
// Usage:
//
//	dnstt-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
//	TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-ADDR TOR_PT_ORPORT=UPSTREAMADDR dnstt-server [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] DOMAIN
//
// Example:
//
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-127.0.0.1:53 TOR_PT_ORPORT=127.0.0.1:8000 dnstt-server -privkey-file server.key t.example.com
//
// To generate a persistent server private key, first run with the -gen-key
// option. By default the generated private and public keys are printed to
// standard output. To save them to files instead, use the -privkey-file and
// -pubkey-file options.
//
//	dnstt-server -gen-key
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//
// You can give the server's private key as a file or as a hex string.
//
//	-privkey-file server.key
//	-privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size at least this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// UPSTREAMADDR is the TCP address to which incoming tunnelled streams will be
// forwarded.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"www.bamsoftware.com/git/dnstt.git/dns"
	serverlib "www.bamsoftware.com/git/dnstt.git/dnstt-server/lib"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

const (
	ptMethodName = "dnstt"
)

var (
	// https://dnsflagday.net/2020/#message-size-considerations
	maxUDPPayload = 1280 - 40 - 8
)

// generateKeypair generates a private key and the corresponding public key.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			log.Printf("deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				log.Printf("cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return noise.ReadKey(f)
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
  TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-ADDR TOR_PT_ORPORT=UPSTREAMADDR %[1]s -privkey-file server.key t.example.com


Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-192.168.0.20:53 TOR_PT_ORPORT=127.0.0.1:8000 %[1]s -privkey-file server.key t.example.com

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if genKey {
		if flag.NArg() != 0 || privkeyString != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			log.Printf("cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		if flag.NArg() != 1 {
			flag.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			log.Printf("invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}

		ptInfo, err := pt.ServerSetup(nil)
		if err != nil {
			log.Fatalf("error in setup: %s", err)
		}

		upstream := ptInfo.OrAddr.String()
		{
			upstreamHost, _, err := net.SplitHostPort(upstream)
			if err != nil {
				log.Printf("cannot parse upstream address %+q: %v\n", upstream, err)
				os.Exit(1)
			}
			upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
			if err != nil {
				log.Printf("warning: cannot resolve upstream host %+q: %v", upstreamHost, err)
			} else if upstreamIPAddr.IP == nil {
				log.Printf("cannot parse upstream address %+q: missing host in address\n", upstream)
				os.Exit(1)
			}
		}

		if pubkeyFilename != "" {
			log.Printf("-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			log.Printf("only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				log.Printf("cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				log.Printf("privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}

		connections := make([]net.PacketConn, 0)
		for _, bindaddr := range ptInfo.Bindaddrs {
			if bindaddr.MethodName != ptMethodName {
				_ = pt.SmethodError(bindaddr.MethodName, "no such method")
				continue
			}

			if bindaddr.Addr.Port == 0 {
				err := fmt.Errorf(
					"cannot listen on port %d; configure a port with TOR_PT_SERVER_BINDADDR",
					bindaddr.Addr.Port)
				log.Printf("error opening listener: %s", err)
				_ = pt.SmethodError(bindaddr.MethodName, err.Error())
				continue
			}

			udpAddr := bindaddr.Addr.String()
			dnsConn, err := net.ListenPacket("udp", udpAddr)
			if err != nil {
				log.Printf("opening UDP listener: %v\n", err)
				_ = pt.SmethodError(bindaddr.MethodName, err.Error())
				continue
			}

			defer func() {
				_ = dnsConn.Close()
			}()

			go func() {
				// No hooks: standard base32 + TXT-only behavior.
				err := serverlib.Run(privkey, domain, upstream, dnsConn, maxUDPPayload, nil)
				if err != nil {
					log.Print(err)
				}
			}()

			pt.SmethodArgs(bindaddr.MethodName, bindaddr.Addr, pt.Args{})
			connections = append(connections, dnsConn)
		}

		pt.SmethodsDone()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)

		if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
			go func() {
				if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
					log.Printf("error copying os.Stdin to ioutil.Discard: %v", err)
				}
				log.Printf("synthesizing SIGTERM because of stdin close")
				sigChan <- syscall.SIGTERM
			}()
		}

		sig := <-sigChan

		log.Printf("caught signal %q, exiting", sig)
		for _, conn := range connections {
			_ = conn.Close()
		}
	}
}
