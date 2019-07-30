package caddytls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cloudflare/backoff"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/gokeyless/conn"
	"github.com/cloudflare/gokeyless/protocol"
	"github.com/lziest/ttlcache"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ed25519"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

/*
	CLIENT
*/

const (
	remoteCacheSize = 512
	remoteCacheTTL  = time.Minute * 5
)

// Client is a Keyless Client capable of connecting to servers and performing keyless operations.
type Client struct {
	// Config is initialized with the client auth configuration used for communicating with keyless servers.
	Config *tls.Config
	// Dialer used to manage connections.
	Dialer *net.Dialer
	// Resolvers is an ordered list of DNS servers used to look up remote servers.
	Resolvers []string
	// DefaultRemote is a default remote to dial and register keys to.
	// TODO: DefaultRemote needs to deal with default server DNS changes automatically.
	// NOTE: For now DefaultRemote is very static to save dns lookup overhead
	DefaultRemote Remote
	// remoteCache maps all known server names to corresponding remote.
	remoteCache *ttlcache.LRU
}

func NewKeylessClientFromFile(caFile string) (*Client, error) {
	pemCerts, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	keyserverCA := x509.NewCertPool()
	if !keyserverCA.AppendCertsFromPEM(pemCerts) {
		return nil, errors.New("gokeyless/client: failed to read keyserver CA from PEM")
	}
	return NewClient(tls.Certificate{}, keyserverCA), nil
}

// NewClient prepares a TLS client capable of connecting to keyservers.
func NewClient(cert tls.Certificate, keyserverCA *x509.CertPool) *Client {
	//Registers Certificate for mutual authentication
	if len(cert.Certificate) == 0 {
		return &Client{
			Config: &tls.Config{
				RootCAs: keyserverCA,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
			},
			Dialer:      &net.Dialer{},
			remoteCache: ttlcache.NewLRU(remoteCacheSize, remoteCacheTTL, nil),
		}
	}
	return &Client{
		Config: &tls.Config{
			RootCAs:      keyserverCA,
			Certificates: []tls.Certificate{cert},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
		Dialer:      &net.Dialer{},
		remoteCache: ttlcache.NewLRU(remoteCacheSize, remoteCacheTTL, nil),
	}
}

// registerSKI associates the SKI of a public key with a particular keyserver.
func (c *Client) getRemote(server string) (Remote, error) {
	// empty server means always associate ski with DefaultRemote
	if server == "" {
		if c.DefaultRemote == nil {
			return nil, fmt.Errorf("default remote is nil")
		}
		return c.DefaultRemote, nil
	}

	v, stale := c.remoteCache.Get(server)
	if v != nil && !stale {
		if r, ok := v.(Remote); ok {
			return r, nil
		}
		log.Error("failed to convert cached remote")
	}

	r, err := c.LookupServer(server)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	c.remoteCache.Set(server, r, 0) // use default timeout
	return r, nil
}

func (c *Client) LoadTLSCertificate(server, certFile string) (cert tls.Certificate, err error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }
	var certPEMBlock []byte
	var certDERBlock *pem.Block

	if certPEMBlock, err = ioutil.ReadFile(certFile); err != nil {
		return fail(err)
	}

	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return fail(errors.New("crypto/tls: failed to parse certificate PEM data"))
	}

	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return fail(err)
	}

	cert.PrivateKey, err = c.newRemoteSigner(server, cert.Leaf)
	if err != nil {
		return fail(err)
	}

	return cert, nil
}

// NewRemoteSigner returns a remote keyserver based crypto.Signer,
// ski, sni, and serverIP are used to identified the key by the remote
// keyserver.
func (c *Client) newRemoteSigner(keyserver string, cert *x509.Certificate) (crypto.Signer, error) {
	pub := cert.PublicKey
	ski, err := protocol.GetSKI(pub)
	if err != nil {
		return nil, err
	}

	priv := PrivateKey{
		public:    pub,
		client:    c,
		ski:       ski,
		sni:       "",
		serverIP:  nil,
		keyserver: keyserver,
	}

	// This is due to an issue in crypto/tls, where an ECDSA key is not allowed to
	// implement Decrypt.
	if _, ok := pub.(*rsa.PublicKey); ok {
		return &Decrypter{priv}, nil
	}
	return &priv, nil
}

/*
	KEY
*/
var (
	rsaCrypto = map[crypto.Hash]protocol.Op{
		crypto.MD5SHA1: protocol.OpRSASignMD5SHA1,
		crypto.SHA1:    protocol.OpRSASignSHA1,
		crypto.SHA224:  protocol.OpRSASignSHA224,
		crypto.SHA256:  protocol.OpRSASignSHA256,
		crypto.SHA384:  protocol.OpRSASignSHA384,
		crypto.SHA512:  protocol.OpRSASignSHA512,
	}
	ecdsaCrypto = map[crypto.Hash]protocol.Op{
		crypto.MD5SHA1: protocol.OpECDSASignMD5SHA1,
		crypto.SHA1:    protocol.OpECDSASignSHA1,
		crypto.SHA224:  protocol.OpECDSASignSHA224,
		crypto.SHA256:  protocol.OpECDSASignSHA256,
		crypto.SHA384:  protocol.OpECDSASignSHA384,
		crypto.SHA512:  protocol.OpECDSASignSHA512,
	}
)

func signOpFromSignerOpts(key *PrivateKey, opts crypto.SignerOpts) protocol.Op {
	if opts, ok := opts.(*rsa.PSSOptions); ok {
		if _, ok := key.Public().(*rsa.PublicKey); !ok {
			return protocol.OpError
		}
		// Keyless only implements RSA-PSS with salt length == hash length,
		// as used in TLS 1.3.  Check that it's what the client is asking,
		// either explicitly or with the magic value.
		if opts.SaltLength != rsa.PSSSaltLengthEqualsHash &&
			opts.SaltLength != opts.Hash.Size() {
			return protocol.OpError
		}
		switch opts.Hash {
		case crypto.SHA256:
			return protocol.OpRSAPSSSignSHA256
		case crypto.SHA384:
			return protocol.OpRSAPSSSignSHA384
		case crypto.SHA512:
			return protocol.OpRSAPSSSignSHA512
		default:
			return protocol.OpError
		}
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		if value, ok := rsaCrypto[opts.HashFunc()]; ok {
			return value
		} else {
			return protocol.OpError
		}
	case *ecdsa.PublicKey:
		if value, ok := ecdsaCrypto[opts.HashFunc()]; ok {
			return value
		} else {
			return protocol.OpError
		}
	case ed25519.PublicKey:
		return protocol.OpEd25519Sign
	default:
		return protocol.OpError
	}
}

// PrivateKey represents a keyless-backed RSA/ECDSA private key.
type PrivateKey struct {
	public    crypto.PublicKey
	client    *Client
	ski       protocol.SKI
	clientIP  net.IP
	serverIP  net.IP
	keyserver string
	sni       string
	certID    string
}

// Public returns the public key corresponding to the opaque private key.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.public
}

// execute performs an opaque cryptographic operation on a server associated
// with the key.
func (key *PrivateKey) execute(op protocol.Op, msg []byte) ([]byte, error) {
	var result *protocol.Operation
	// retry once if connection returned by remote Dial is problematic.
	for attempts := 2; attempts > 0; attempts-- {
		r, err := key.client.getRemote(key.keyserver)
		if err != nil {
			return nil, err
		}

		conn, err := r.Dial(key.client)
		if err != nil {
			return nil, err
		}

		result, err = conn.Conn.DoOperation(protocol.Operation{
			Opcode:   op,
			Payload:  msg,
			SKI:      key.ski,
			ClientIP: key.clientIP,
			ServerIP: key.serverIP,
			SNI:      key.sni,
			CertID:   key.certID,
		})
		if err != nil {
			conn.Close()
			// not the last attempt, log error and retry
			if attempts > 1 {
				log.Info("failed remote operation:", err)
				log.Infof("retry new connction")
				continue
			}
			return nil, err
		}
		conn.KeepAlive()
		break
	}

	if result.Opcode != protocol.OpResponse {
		if result.Opcode == protocol.OpError {
			return nil, result.GetError()
		}
		return nil, fmt.Errorf("wrong response opcode: %v", result.Opcode)
	}

	if len(result.Payload) == 0 {
		return nil, errors.New("empty payload")
	}

	return result.Payload, nil
}

// Sign implements the crypto.Signer operation for the given key.
func (key *PrivateKey) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	// If opts specifies a hash function, then the message is expected to be the
	// length of the output of that hash function.
	if opts.HashFunc() != 0 && len(msg) != opts.HashFunc().Size() {
		return nil, errors.New("input must be hashed message")
	}

	op := signOpFromSignerOpts(key, opts)
	if op == protocol.OpError {
		return nil, errors.New("invalid key type, hash or options")
	}
	return key.execute(op, msg)
}

// Decrypter implements the Decrypt method on a PrivateKey.
type Decrypter struct {
	PrivateKey
}

// Decrypt implements the crypto.Decrypter operation for the given key.
func (key *Decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	opts1v15, ok := opts.(*rsa.PKCS1v15DecryptOptions)
	if opts != nil && !ok {
		return nil, errors.New("invalid options for Decrypt")
	}

	ptxt, err := key.execute(protocol.OpRSADecrypt, msg)
	if err != nil {
		return nil, err
	}

	if ok {
		if l := opts1v15.SessionKeyLen; l > 0 {
			key := make([]byte, opts1v15.SessionKeyLen)
			if _, err := io.ReadFull(rand, key); err != nil {
				return nil, err
			} else if err = stripPKCS1v15SessionKey(ptxt, key); err != nil {
				return nil, err
			}
			return key, nil
		}
		return stripPKCS1v15(ptxt)
	}
	return ptxt, nil
}

func stripPKCS1v15(em []byte) ([]byte, error) {
	valid, index := parsePKCS1v15(em)
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return em[index:], nil
}

func stripPKCS1v15SessionKey(em, key []byte) error {
	if len(em)-(len(key)+3+8) < 0 {
		return rsa.ErrDecryption
	}

	valid, index := parsePKCS1v15(em)
	valid &= subtle.ConstantTimeEq(int32(len(em)-index), int32(len(key)))
	subtle.ConstantTimeCopy(valid, key, em[len(em)-len(key):])
	return nil
}

func parsePKCS1v15(em []byte) (valid, index int) {
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return
}

/*
	REMOTE
*/

const (
	connPoolSize = 512
	defaultTTL   = 1 * time.Hour
)

// TestDisableConnectionPool allows the connection pooling to be disabled during
// tests which require concurrency.
var TestDisableConnectionPool uint32

// connPoolType is a async safe pool of established gokeyless Conn
// so we don't need to do TLS handshake unnecessarily.
type connPoolType struct {
	pool *ttlcache.LRU
}

// connPool keeps all active Conn
var connPool *connPoolType

// A Remote represents some number of remote keyless server(s)
type Remote interface {
	Dial(*Client) (*Conn, error)
	PingAll(*Client, int)
}

// A Conn represents a long-lived client connection to a keyserver.
type Conn struct {
	*conn.Conn
	addr string
	done chan struct{}
}

// A singleRemote is an individual remote server
type singleRemote struct {
	net.Addr          // actual address
	ServerName string // hostname for TLS verification
}

func init() {
	connPool = &connPoolType{
		pool: ttlcache.NewLRU(connPoolSize, defaultTTL, nil),
	}
}

// NewConn creates a new Conn based on a conn.Conn and spawns a goroutine to
// periodically check that it is healthy. This goroutine will automatically
// quit if it detects that the connection has been closed.
func NewConn(addr string, conn *conn.Conn) *Conn {
	c := &Conn{
		Conn: conn,
		addr: addr,
		done: make(chan struct{}, 1),
	}
	go healthchecker(c)
	return c
}

// NewStandaloneConn creates a new Conn based on a conn.Conn. Unlike NewConn,
// no health-checking goroutine is spawned.
func NewStandaloneConn(addr string, conn *conn.Conn) *Conn {
	return &Conn{
		Conn: conn,
		addr: addr,
	}
}

// Close closes a Conn and remove it from the conn pool
func (conn *Conn) Close() error {
	// TODO(joshlf): This function seems fishy because it's meant to interact with
	// the pool, and thus could close a connection out from somebody else's feet.
	connPool.Remove(conn.addr)
	// Try sending on the buffered channel, but only if it immediately succeeds.
	// We need to do this rather than closing the channel since Close may be
	// called multiple times.
	select {
	case conn.done <- struct{}{}:
	default:
		break
	}
	return conn.Conn.Close()
}

// KeepAlive keeps Conn reusable in the conn pool
func (conn *Conn) KeepAlive() {
	connPool.Add(conn.addr, conn)
}

// healthchecker is a recurrent timer function that tests the connections
func healthchecker(c *Conn) {
	b := backoff.NewWithoutJitter(1*time.Hour, 1*time.Second)
	// automatic reset timer to 1*second,  if backoff is greater than 20 minutes.
	b.SetDecay(20 * time.Minute)

	for {
		select {
		case <-time.After(b.Duration()):
			break
		case <-c.done:
			return
		}

		err := c.Conn.Ping(nil)
		if err != nil {
			if err == conn.ErrClosed {
				// somebody else closed the connection while we were sleeping
				return
			}
			log.Debug("health check ping failed:", err)
			// shut down the conn and remove it from the conn pool.
			c.Close()
			return
		}

		log.Debug("start a new health check timer")
	}
}

// Get returns a Conn from the pool if there is any.
func (p *connPoolType) Get(key string) *Conn {
	if atomic.LoadUint32(&TestDisableConnectionPool) == 1 {
		return nil
	}
	// ignore stale indicator
	value, _ := p.pool.Get(key)
	conn, ok := value.(*Conn)
	if ok {
		return conn
	}
	return nil
}

// Add adds a Conn to the pool.
func (p *connPoolType) Add(key string, conn *Conn) {
	if atomic.LoadUint32(&TestDisableConnectionPool) == 1 {
		return
	}
	p.pool.Set(key, conn, defaultTTL)
	log.Debug("add conn with key:", key)
}

// Remove removes a Conn keyed by key.
func (p *connPoolType) Remove(key string) {
	if atomic.LoadUint32(&TestDisableConnectionPool) == 1 {
		return
	}
	p.pool.Remove(key)
	log.Debug("remove conn with key:", key)
}

// NewServer creates a new remote based a given addr and server name.
func NewServer(addr net.Addr, serverName string) Remote {
	return &singleRemote{
		Addr:       addr,
		ServerName: serverName,
	}
}

// UnixRemote returns a Remote constructed from the Unix address
func UnixRemote(unixAddr, serverName string) (Remote, error) {
	addr, err := net.ResolveUnixAddr("unix", unixAddr)
	if err != nil {
		return nil, err
	}

	return NewServer(addr, serverName), nil
}

// LookupIPs resolves host with resolvers list sequentially unitl one resolver
// can answer the request. It falls back to use system default for final
// resolution if none of resolvers can answer.
func LookupIPs(resolvers []string, host string) (ips []net.IP, err error) {
	m := new(dns.Msg)
	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"
	for _, resolver := range resolvers {
		m.SetQuestion(dns.Fqdn(host), dns.TypeA)
		if in, _, err := dnsClient.Exchange(m, resolver); err == nil {
			for _, rr := range in.Answer {
				if a, ok := rr.(*dns.A); ok {
					log.Debugf("resolve %s to %s", host, a)
					ips = append(ips, a.A)
				}
			}
		} else {
			log.Warningf("fail to get A records for %s with %s: %v", host, resolver, err)
		}

		m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		if in, _, err := dnsClient.Exchange(m, resolver); err == nil {
			for _, rr := range in.Answer {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					log.Debugf("resolve %s to %s", host, aaaa)
					ips = append(ips, aaaa.AAAA)
				}
			}
		} else {
			log.Warningf("fail to get AAAA records for %s with %s: %v", host, resolver, err)
		}
	}
	if len(ips) != 0 {
		return ips, nil
	}

	return net.LookupIP(host)
}

// LookupServer with default ServerName.
func (c *Client) LookupServer(hostport string) (Remote, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}

	ips, err := LookupIPs(c.Resolvers, host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("fail to resolve %s", host)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	var servers []Remote
	for _, ip := range ips {
		addr := &net.TCPAddr{IP: ip, Port: portNumber}
		servers = append(servers, NewServer(addr, host))
	}
	log.Infof("server lookup: %s has %d usable upstream", host, len(servers))
	return NewGroup(servers)
}

// Dial dials a remote server, returning an existing connection if possible.
func (s *singleRemote) Dial(c *Client) (*Conn, error) {
	cn := connPool.Get(s.String())
	if cn != nil {
		return cn, nil
	}

	config := c.Config.Clone()
	config.ServerName = s.ServerName
	log.Debugf("Dialing %s at %s\n", s.ServerName, s.String())
	inner, err := tls.DialWithDialer(c.Dialer, s.Network(), s.String(), config)
	if err != nil {
		return nil, err
	}

	cn = NewConn(s.String(), conn.NewConn(inner))
	connPool.Add(s.String(), cn)
	go func() {
		for {
			err := cn.Conn.DoRead()
			if err != nil {
				if err == io.EOF {
					log.Debugf("connection %v: closed by server", inner.RemoteAddr())
				} else {
					log.Errorf("connection %v: failed to read next header from %v: %v", inner.RemoteAddr(), s.String(), err)
				}
				break
			}
		}

		cn.Close()
	}()

	return cn, nil
}

// PingAll simply attempts to ping the singleRemote
func (s *singleRemote) PingAll(c *Client, concurrency int) {
	cn, err := s.Dial(c)
	if err != nil {
		return
	}

	err = cn.Conn.Ping(nil)
	if err != nil {
		cn.Close()
	}
}

// ewmaLatency is exponentially weighted moving average of latency
type ewmaLatency struct {
	val      time.Duration
	measured bool
}

func (l ewmaLatency) Update(val time.Duration) {
	l.measured = true
	l.val /= 2
	l.val += (val / 2)
}

func (l ewmaLatency) Reset() {
	l.val = 0
	l.measured = false
}

func (l ewmaLatency) Better(r ewmaLatency) bool {
	// if l is not measured (it also means last measurement was
	// a failure), any updated/measured latency is better than
	// l. Also if neither l or r is measured, l can't be better
	// than r.
	if !l.measured {
		return false
	}

	if l.measured && !r.measured {
		return true
	}

	return l.val < r.val
}

// mRemote denotes Remote with latency measurements.
type mRemote struct {
	Remote
	latency ewmaLatency
}

type mRemoteSorter []mRemote

// A Group is a Remote consisting of a load-balanced set of external servers.
type Group struct {
	sync.RWMutex
	remotes     []mRemote
	lastPingAll time.Time
}

// NewGroup creates a new group from a set of remotes.
func NewGroup(remotes []Remote) (*Group, error) {
	if len(remotes) == 0 {
		return nil, errors.New("attempted to create empty remote group")
	}
	g := new(Group)

	for _, r := range remotes {
		g.remotes = append(g.remotes, mRemote{Remote: r})
	}

	return g, nil
}

// Dial returns a connection with best latency measurement.
func (g *Group) Dial(c *Client) (conn *Conn, err error) {
	g.RLock()
	if len(g.remotes) == 0 {
		err = errors.New("remote group empty")
		return nil, err
	}
	// n is the number of trials.
	// Because of potential expensive fresh tls dial operation,
	// we limit total dial candidates to a small number.
	// Also it solves a subtle problem of test 'localhost'
	// server discovery due to dual ipv6/ipv4 ip resolution.
	n := 3
	if len(g.remotes) < n {
		n = len(g.remotes)
	}

	remotes := make([]mRemote, n)
	// copy and shuffle first n remotes for load balancing
	for i := 0; i < n; i++ {
		j := rand.Intn(i + 1)
		if i != j {
			remotes[i] = remotes[j]
		}
		remotes[j] = g.remotes[i]
	}
	g.RUnlock()

	defer func() {
		g.Lock()
		if time.Since(g.lastPingAll) > 30*time.Minute {
			g.lastPingAll = time.Now()
			go g.PingAll(c, 1)
		}
		g.Unlock()

	}()

	for _, r := range remotes {
		conn, err = r.Dial(c)
		if err != nil {
			log.Debugf("retry due to dial failure: %v", err)
		} else {
			break
		}
	}

	return conn, err
}

// PingAll loops through all remote servers for performance measurement
// in a separate goroutine. It allows a separate goroutine to
// asynchronously sort remotes by ping latencies. It also serves
// as a service discovery tool.
func (g *Group) PingAll(c *Client, concurrency int) {
	g.RLock()
	remotes := make([]mRemote, len(g.remotes))
	copy(remotes, g.remotes)
	g.RUnlock()

	if concurrency <= 0 {
		concurrency = 1
	}
	// ch receives all tested remote back
	ch := make(chan mRemote, len(remotes))
	// jobQueue controls concurrency
	jobQueue := make(chan bool, concurrency)
	// fill the queue
	for i := 0; i < cap(jobQueue); i++ {
		jobQueue <- true
	}

	// each goroutine dials a remote
	for _, r := range remotes {
		// take a job slot from the queue
		<-jobQueue
		go func(r mRemote) {
			// defer returns a job slot to the queue
			defer func() { jobQueue <- true }()
			cn, err := r.Dial(c)
			if err != nil {
				r.latency.Reset()
				log.Infof("PingAll's dial failed: %v", err)
				ch <- r
				return
			}

			start := time.Now()
			err = cn.Conn.Ping(nil)
			duration := time.Since(start)

			if err != nil {
				defer cn.Close()
				r.latency.Reset()
				log.Infof("PingAll's ping failed: %v", err)
			} else {
				r.latency.Update(duration)
			}
			ch <- r
		}(r)
	}

	for i := 0; i < len(remotes); i++ {
		remotes[i] = <-ch
	}

	sort.Sort(mRemoteSorter(remotes))

	g.Lock()
	g.remotes = remotes
	g.lastPingAll = time.Now()
	g.Unlock()
}

// Len(), Less(i, j) and Swap(i,j) implements sort.Interface

// Len returns the number of remote
func (s mRemoteSorter) Len() int {
	return len(s)
}

// Swap swaps remote i and remote j in the list
func (s mRemoteSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less compares two Remotes at position i and j based on latency
func (s mRemoteSorter) Less(i, j int) bool {
	pi, pj := s[i].latency, s[j].latency
	return pi.Better(pj)
}
