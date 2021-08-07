package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"syscall"

	"myproxy/socks5"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type Socks5Config struct {
	*socks5.DefConfig
	dial func(string) (net.Conn, error)
}

func (s *Socks5Config) DialTCP(addr string) (net.Conn, error) {
	return s.dial(addr)
}

func main() {
	username := os.Getenv("USER")
	keypath := os.Getenv("HOME") + "/.ssh/id_rsa"
	knownhosts_path := os.Getenv("HOME") + "/.ssh/known_hosts"

	key, err := ioutil.ReadFile(keypath)
	if err != nil {
		log.Fatalf("failed to read private key at %s: %v", keypath, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	switch err.(type) {
	case nil:
	case *ssh.PassphraseMissingError:
		fmt.Printf("enter password for %s: ", keypath)
		passwd, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("failed to read password: %v", err)
		}
		fmt.Println()
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, passwd)
		if err != nil {
			log.Fatalf("failed to decrypt private key: %v", err)
		}
	default:
		log.Fatalf("failed to parse private key: %v", err)
	}

	knownhosts_callback, err := knownhosts.New(knownhosts_path)
	if err != nil {
		log.Fatalf("failed to read known_hosts file at %s: %v", knownhosts_path, err)
	}

	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	sshconf := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: knownhosts_callback,
	}

	type Resp struct {
		client *ssh.Client
		err    error
	}

	poolsize := 10
	reqchan := make([]chan int, poolsize)
	respchan := make([]chan Resp, poolsize)
	rngchan := make(chan int, poolsize)

	for i := range reqchan {
		reqchan[i] = make(chan int)
		respchan[i] = make(chan Resp)
		go func(i int) {
			var resp Resp
			deadchan := make(chan error)
			for {
				<-reqchan[i]
				select {
				case err := <-deadchan:
					resp = Resp{err: err}
					log.Printf("ssh connection dead due to: %v\n", err)
				default:
				}
				if resp.client == nil {
					log.Println("trying to create new ssh connection")
					client, err := ssh.Dial("tcp", "vultr-tokyo-1.qwwp.ml:22", sshconf)
					if err != nil {
						log.Printf("ssh dial failed due to: %v\n", err)
					} else {
						log.Println("established new ssh connection")
						go func() { deadchan <- client.Wait() }()
					}
					resp = Resp{client: client, err: err}
				}
				respchan[i] <- resp
			}
		}(i)
	}

	go func() {
		for {
			rngchan <- rand.Intn(poolsize)
		}
	}()

	socks5Conf := &Socks5Config{
		DefConfig: socks5.NewDefConfig(),
		dial: func(addr string) (net.Conn, error) {
			i := <-rngchan
			log.Println("getting ssh connection from pool")
			reqchan[i] <- 0
			log.Println("request sent")
			resp := <-respchan[i]
			log.Println("got response")
			if resp.err != nil {
				return nil, resp.err
			}
			log.Println("creating ssh channel")
			return resp.client.Dial("tcp", addr)
		},
	}
	socks5Conf.Port = "8080"

	socksserver := socks5.NewSocks5Server(socks5Conf)

	socksserver.Listen()
}
