// Package lib provides the core dnstt server logic with pluggable hooks
// for payload decoding and response handling. External modules can override
// the default base32 decoding by supplying custom hooks.
package lib

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	IdleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	ResponseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	MaxResponseDelay = 1 * time.Second

	// How long to wait for a TCP connection to upstream to be established.
	UpstreamDialTimeout = 30 * time.Second
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// DecodeFunc decodes subdomain prefix labels into a binary payload.
// It receives the labels that precede the tunnel domain.
type DecodeFunc func(prefix dns.Name) ([]byte, error)

// NonTXTResponseFunc builds response data for non-TXT query types (e.g. A, AAAA).
// Returns the RR data bytes, or nil if the query type is not handled.
type NonTXTResponseFunc func(qtype uint16) []byte

// ServerHooks allows external modules to plug custom decoding and response
// behavior into the dnstt server. This follows the same pattern as
// DNSPacketConnHooks in dnstt-client/lib.
type ServerHooks struct {
	// DecodePayload, if non-nil, replaces the default base32 decoder.
	DecodePayload DecodeFunc

	// AcceptQueryType, if non-nil, determines which query types are
	// processed. The default accepts only TXT.
	AcceptQueryType func(qtype uint16) bool

	// HandleNonTXT, if non-nil, is called for accepted non-TXT queries
	// to produce a response. The default behavior is NXDOMAIN for non-TXT.
	HandleNonTXT NonTXTResponseFunc
}

// defaultDecode is the standard base32 decoder used by upstream dnstt.
func defaultDecode(prefix dns.Name) ([]byte, error) {
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		return nil, err
	}
	return payload[:n], nil
}

// defaultAcceptQueryType accepts only TXT queries.
func defaultAcceptQueryType(qtype uint16) bool {
	return qtype == dns.RRTypeTXT
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
func responseFor(query *dns.Message, domain dns.Name, maxUDPPayload int, hooks *ServerHooks) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		return nil, nil
	}

	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}

	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	acceptQtype := defaultAcceptQueryType
	if hooks != nil && hooks.AcceptQueryType != nil {
		acceptQtype = hooks.AcceptQueryType
	}
	if !acceptQtype(question.Type) {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}

	decode := defaultDecode
	if hooks != nil && hooks.DecodePayload != nil {
		decode = hooks.DecodePayload
	}
	payload, err := decode(prefix)
	if err != nil {
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: decoding: %v", err)
		return resp, nil
	}

	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, maxUDPPayload)
		return resp, nil
	}

	return resp, payload
}

// handleStream bidirectionally connects a client stream with a TCP socket.
func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: UpstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer func() {
		_ = upstreamConn.Close()
	}()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
		}
		_ = upstreamTCPConn.CloseRead()
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
		}
		_ = upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer func() {
		_ = sess.Close()
	}()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				_ = stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if rc := conn.SetMtu(mtu); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				_ = conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// recvLoop extracts packets from incoming DNS queries.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, maxUDPPayload int, hooks *ServerHooks) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		resp, payload := responseFor(&query, domain, maxUDPPayload, hooks)
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				ttConn.QueueIncoming(p, clientID)
			}
		} else {
			if resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				log.Printf("NXDOMAIN: %d bytes are too short to contain a ClientID", n)
			}
		}
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID}:
			default:
			}
		}
	}
}

// sendLoop sends DNS responses, packing downstream data into TXT answers.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int, maxUDPPayload int, hooks *ServerHooks) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			qtype := rec.Resp.Question[0].Type

			// Check if a hook wants to handle non-TXT responses.
			if qtype != dns.RRTypeTXT && hooks != nil && hooks.HandleNonTXT != nil {
				if data := hooks.HandleNonTXT(qtype); data != nil {
					rec.Resp.Answer = []dns.RR{
						{
							Name:  rec.Resp.Question[0].Name,
							Type:  qtype,
							Class: rec.Resp.Question[0].Class,
							TTL:   ResponseTTL,
							Data:  data,
						},
					}
					goto send
				}
			}

			if qtype == dns.RRTypeTXT {
				rec.Resp.Answer = []dns.RR{
					{
						Name:  rec.Resp.Question[0].Name,
						Type:  rec.Resp.Question[0].Type,
						Class: rec.Resp.Question[0].Class,
						TTL:   ResponseTTL,
						Data:  nil,
					},
				}

				var payload bytes.Buffer
				limit := maxEncodedPayload
				timer := time.NewTimer(MaxResponseDelay)
				for {
					var p []byte
					unstash := ttConn.Unstash(rec.ClientID)
					outgoing := ttConn.OutgoingQueue(rec.ClientID)
					select {
					case p = <-unstash:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						default:
							select {
							case p = <-unstash:
							case p = <-outgoing:
							case <-timer.C:
							case nextRec = <-ch:
							}
						}
					}
					timer.Reset(0)

					if len(p) == 0 {
						break
					}

					limit -= 2 + len(p)
					if payload.Len() == 0 {
						// Allow first packet even if oversized.
					} else if limit < 0 {
						ttConn.Stash(p, rec.ClientID)
						break
					}
					if int(uint16(len(p))) != len(p) {
						panic(len(p))
					}
					_ = binary.Write(&payload, binary.BigEndian, uint16(len(p)))
					payload.Write(p)
				}
				timer.Stop()

				rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payload.Bytes())
			}
		}

	send:
		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		if len(buf) > maxUDPPayload {
			log.Printf("truncating response of %d bytes to max of %d", len(buf), maxUDPPayload)
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02 // TC = 1
		}

		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("WriteTo temporary error: %v", err)
				continue
			}
			return err
		}
	}
	return nil
}

// ComputeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keeps the overall response size under the given limit.
func ComputeMaxEncodedPayload(limit int) int {
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  dns.RRTypeTXT,
				Class: dns.RRTypeTXT,
			},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, [][]byte{}, limit, nil)
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   ResponseTTL,
			Data:  nil,
		},
	}

	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

// Run starts the dnstt server with the given configuration and optional hooks.
// If hooks is nil, the server behaves identically to upstream dnstt (base32, TXT-only).
func Run(privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, maxUDPPayload int, hooks *ServerHooks) error {
	defer func() {
		_ = dnsConn.Close()
	}()

	log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))

	maxEncodedPayload := ComputeMaxEncodedPayload(maxUDPPayload)
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, IdleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer func() {
		_ = ln.Close()
	}()
	go func() {
		err := acceptSessions(ln, privkey, mtu, upstream)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	ch := make(chan *record, 100)
	defer close(ch)

	go func() {
		err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload, maxUDPPayload, hooks)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()

	return recvLoop(domain, dnsConn, ttConn, ch, maxUDPPayload, hooks)
}
