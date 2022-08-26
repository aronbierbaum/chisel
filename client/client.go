package chclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jpillora/backoff"
	"github.com/jpillora/chisel/share"
	"golang.org/x/crypto/ssh"
)

//Config represents a client configuration
type Config struct {
	shared           *chshare.Config
	Fingerprint      string
	Auth             string
	KeepAlive        time.Duration
	MaxRetryCount    int
	MaxRetryInterval time.Duration
	Server           string
	HTTPProxy        string
	Remotes          []string
}

//Client represents a client instance
type Client struct {
	*chshare.Logger
	config       *Config
	sshConfig    *ssh.ClientConfig
	proxies      []*tcpProxy
	sshConn      ssh.Conn
	httpProxyURL *url.URL
	server       string
	running      bool
	runningc     chan error
}

//NewClient creates a new client instance
func NewClient(config *Config) (*Client, error) {
	//apply default scheme
	if !strings.HasPrefix(config.Server, "http") {
		config.Server = "http://" + config.Server
	}
	if config.MaxRetryInterval < time.Second {
		config.MaxRetryInterval = 5 * time.Minute
	}
	u, err := url.Parse(config.Server)
	if err != nil {
		return nil, err
	}
	//apply default port
	if !regexp.MustCompile(`:\d+$`).MatchString(u.Host) {
		if u.Scheme == "https" || u.Scheme == "wss" {
			u.Host = u.Host + ":443"
		} else {
			u.Host = u.Host + ":80"
		}
	}
	//swap to websockets scheme
	u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
	shared := &chshare.Config{}
	for _, s := range config.Remotes {
		r, err := chshare.DecodeRemote(s)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode remote '%s': %s", s, err)
		}
		shared.Remotes = append(shared.Remotes, r)
	}
	config.shared = shared
	client := &Client{
		Logger:   chshare.NewLogger("client"),
		config:   config,
		server:   u.String(),
		running:  true,
		runningc: make(chan error, 1),
	}
	client.Info = true

	if p := config.HTTPProxy; p != "" {
		client.httpProxyURL, err = url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("Invalid proxy URL (%s)", err)
		}
	}

	user, pass := chshare.ParseAuth(config.Auth)

	client.sshConfig = &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		ClientVersion:   "SSH-" + chshare.ProtocolVersion + "-client",
		HostKeyCallback: client.verifyServer,
		Timeout:         30 * time.Second,
	}

	return client, nil
}

//Run starts client and blocks while connected
func (c *Client) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	// Wait on stdin so that process terminates with parent process.
	bytes, _ := ioutil.ReadAll(os.Stdin)
	c.Infof("Exiting... %s", bytes)
	return nil
}

func (c *Client) verifyServer(hostname string, remote net.Addr, key ssh.PublicKey) error {
	expect := c.config.Fingerprint
	got := chshare.FingerprintKey(key)
	if expect != "" && !strings.HasPrefix(got, expect) {
		return fmt.Errorf("Invalid fingerprint (%s)", got)
	}
	//overwrite with complete fingerprint
	c.Infof("Fingerprint %s", got)
	return nil
}

//Start client and does not block
func (c *Client) Start() error {
	via := ""
	if c.httpProxyURL != nil {
		via = " via " + c.httpProxyURL.String()
	}
	//prepare proxies
	for i, r := range c.config.shared.Remotes {
		proxy := newTCPProxy(c, i, r)
		if err := proxy.start(); err != nil {
			return err
		}
		c.proxies = append(c.proxies, proxy)
	}
	c.Infof("Connecting to %s%s\n", c.server, via)
	//
	go c.loop()
	return nil
}

func (c *Client) loop() {
	//optional keepalive loop
	if c.config.KeepAlive > 0 {
		go func() {
			for range time.Tick(c.config.KeepAlive) {
				if c.sshConn != nil {
					c.sshConn.SendRequest("ping", true, nil)
				}
			}
		}()
	}
	//connection loop!
	var connerr error
	b := &backoff.Backoff{Max: c.config.MaxRetryInterval}
	for {
		if !c.running {
			break
		}
		if connerr != nil {
			attempt := int(b.Attempt())
			maxAttempt := c.config.MaxRetryCount
			d := b.Duration()
			//show error and attempt counts
			msg := fmt.Sprintf("Connection error: %s", connerr)
			if attempt > 0 {
				msg += fmt.Sprintf(" (Attempt: %d", attempt)
				if maxAttempt > 0 {
					msg += fmt.Sprintf("/%d", maxAttempt)
				}
				msg += ")"
			}
			c.Debugf(msg)
			//give up?
			if maxAttempt >= 0 && attempt >= maxAttempt {
				break
			}
			c.Infof("Retrying in %s...", d)
			connerr = nil
			chshare.SleepSignal(d)
		}
		d := websocket.Dialer{
			ReadBufferSize:   1024,
			WriteBufferSize:  1024,
			HandshakeTimeout: 45 * time.Second,
			Subprotocols:     []string{chshare.ProtocolVersion},
		}
		//optionally CONNECT proxy
		if c.httpProxyURL != nil {
			d.Proxy = func(*http.Request) (*url.URL, error) {
				return c.httpProxyURL, nil
			}
		}
		wsConn, _, err := d.Dial(c.server, nil)
		if err != nil {
			connerr = err
			continue
		}
		conn := chshare.NewWebSocketConn(wsConn)
		// perform SSH handshake on net.Conn
		c.Debugf("Handshaking...")
		sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", c.sshConfig)
		if err != nil {
			if strings.Contains(err.Error(), "unable to authenticate") {
				c.Infof("Authentication failed")
				c.Debugf(err.Error())
			} else {
				c.Infof(err.Error())
			}
			break
		}
		c.config.shared.Version = chshare.BuildVersion
		conf, _ := chshare.EncodeConfig(c.config.shared)
		c.Debugf("Sending config")
		t0 := time.Now()
		_, configerr, err := sshConn.SendRequest("config", true, conf)
		if err != nil {
			c.Infof("Config verification failed")
			break
		}
		if len(configerr) > 0 {
			c.Infof(string(configerr))
			break
		}
		c.Infof("Connected (Latency %s)", time.Since(t0))
		//connected
		b.Reset()
		c.sshConn = sshConn
		go ssh.DiscardRequests(reqs)
		go chshare.RejectStreams(chans) //TODO allow client to ConnectStreams
		err = sshConn.Wait()
		//disconnected
		c.sshConn = nil
		if err != nil && err != io.EOF {
			connerr = err
			continue
		}
		c.Infof("Disconnected\n")
	}
	close(c.runningc)
}

//Wait blocks while the client is running.
//Can only be called once.
func (c *Client) Wait() error {
	return <-c.runningc
}

//Close manual stops the client
func (c *Client) Close() error {
	c.running = false
	if c.sshConn == nil {
		return nil
	}
	return c.sshConn.Close()
}

// ====================================

/**
 * Connect to the server and starts remote proxies.
 */
func (c *Client) Connect(tlsConfig *tls.Config, maxAttempts int) error {
   via := ""
   if c.httpProxyURL != nil {
      via = " via " + c.httpProxyURL.String()
   }
   c.Infof("Connecting to %s%s\n", c.server, via)

   var connerr error
   connect_backoff := &backoff.Backoff{Max: 5 * time.Minute}
   for {
      // Early out if we called Disconnect
      if !c.running {
         return errors.New("Already disconnected")
      }

      // Display error details if previous attempt failed.
      if connerr != nil {
         attempt := int(connect_backoff.Attempt())
         duration := connect_backoff.Duration()

         msg := fmt.Sprintf("Connection error: %s", connerr)
         if attempt > 0 {
            msg += fmt.Sprintf(" (Attempt: %d", attempt)
            if maxAttempts > 0 {
               msg += fmt.Sprintf("/%d", maxAttempts)
            }
            msg += ")"
         }
         c.Infof(msg)

         // Give up if we have reached the maximum number of attempts.
         if maxAttempts >= 0 && attempt >= maxAttempts {
            return errors.New(fmt.Sprintf("Failed to connect after %d attempts", attempt))
         }

         connerr = nil
         chshare.SleepSignal(duration)
      }

      // Construct dialer that is used to connect to server.
      dialer := websocket.Dialer{
         ReadBufferSize:  1024,
         WriteBufferSize: 1024,
         Subprotocols:    []string{chshare.ProtocolVersion},
         TLSClientConfig: tlsConfig,
      }

      // Optionally add CONNECT proxy
      if c.httpProxyURL != nil {
         dialer.Proxy = func(*http.Request) (*url.URL, error) {
            return c.httpProxyURL, nil
         }
      }

      // Connect to the HTTP server using websockets.
      wsConn, _, err := dialer.Dial(c.server, nil)
      if err != nil {
         connerr = err
         continue
      }

      // Perform SSH handshake on net.Conn
      c.Debugf("Handshaking...")
      conn := chshare.NewWebSocketConn(wsConn)
      sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", c.sshConfig)
      // Early out if websocket connection failed.
      if err != nil {
         if strings.Contains(err.Error(), "unable to authenticate") {
            c.Infof("Authentication failed")
            c.Debugf(err.Error())
            err = errors.New("Authentication failed")
         } else {
            c.Infof(err.Error())
         }
         wsConn.Close()

         return err
      }

      // Attempt to send configuration
      c.config.shared.Version = chshare.BuildVersion
      conf, _ := chshare.EncodeConfig(c.config.shared)
      c.Debugf("Sending config")
      t0 := time.Now()
      _, configerr, err := sshConn.SendRequest("config", true, conf)
      if err != nil {
         c.Infof("Config verification failed")
         return errors.New("Config verification failed");
      }

      // Early out if sending configuration failed.
      if len(configerr) > 0 {
         c.Infof(string(configerr))
         sshConn.Close()
         return errors.New(string(configerr))
      }

      // At this point we are connected. We indicate that be setting sshCon.
      c.Infof("Connected (Latency %s)", time.Since(t0))
      connect_backoff.Reset()
      c.sshConn = sshConn

      // Discard requests and reject all tunnels.
      go ssh.DiscardRequests(reqs)
      go chshare.RejectStreams(chans)
      break;
   }

   // Early out if we are not connected.
   if c.sshConn == nil {
      close(c.runningc)
      return nil;
   }

   // Optionally create a ticker for keepalive.
   var ticker *time.Ticker = nil;
   if c.config.KeepAlive > 0 {
      ticker = time.NewTicker(c.config.KeepAlive)
      go func() {
         for range ticker.C {
            if c.sshConn != nil {
               c.sshConn.SendRequest("ping", true, nil)
            }
         }
      }()
   }

   // Start all of the proxies
   for i, r := range c.config.shared.Remotes {
      proxy := newTCPProxy(c, i, r)
      if err := proxy.start(); err != nil {
         return err
      }
      c.proxies = append(c.proxies, proxy)
   }

   go func() {
      // Wait for connection to be lost.
      err := c.sshConn.Wait()

      // Display error message about disconnect.
      if err != nil && err != io.EOF {
         if !strings.Contains(err.Error(), "use of closed network connection") {
            c.Infof("Disconnected error: %s", err)
         }
      }

      // Stop and clear all proxies.
      for _, proxy := range c.proxies {
         proxy.stop()
      }
      c.proxies = nil;

      // Stop the keepalive ticker
      if ticker != nil {
         ticker.Stop()
         ticker = nil
         c.Infof("Keep alive ticker stopped")
      }

      // At this point we are disconnected. We indicate that be setting sshCon to nul.
      c.sshConn = nil

      close(c.runningc)
   }()

   return nil;
}


/**
 * Disconnect from the server.
 */
func (c *Client) Disconnect() error {
   c.running = false

   if c.sshConn == nil {
      return nil
   }

   c.Infof("Disconnecting")

   // Start the process of closing the connection
   err := c.sshConn.Close()
   if err != nil {
      c.Infof("Failed to disconnect")
      return err;
   }

   c.Infof("Disconnected")

   return nil;
}
