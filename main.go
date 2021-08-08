package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"syscall"

	"sshproxy/socks5"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type DummyResolver struct{}

func (*DummyResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, net.IP{}, nil
}

func main() {
	listenaddr := flag.String("l", "127.0.0.1:1080", "listening address")
	poolsize := flag.Uint("p", 1, "connection pool size")

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s [OPTIONS] remote\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	remoteurl, err := url.Parse("ssh://" + flag.Arg(0))
	if err != nil {
		log.Fatalf("failed to parse remote url %v\n", err)
	}
	if remoteurl.Port() == "" {
		remoteurl.Host = net.JoinHostPort(remoteurl.Hostname(), "22")
	}
	username := remoteurl.User.Username()
	if username == "" {
		username = os.Getenv("USER")
	}
	// log.Printf("host is %s\n", remoteurl.Host)
	// log.Printf("username is %s\n", username)
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

	reqchan := make([]chan int, *poolsize)
	respchan := make([]chan Resp, *poolsize)
	rngchan := make(chan int, *poolsize)

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
					log.Printf("ssh connection died due to: %v\n", err)
				default:
				}
				if resp.client == nil {
					log.Println("trying to create new ssh connection")
					client, err := ssh.Dial("tcp", remoteurl.Host, sshconf)
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
			rngchan <- rand.Intn(int(*poolsize))
		}
	}()

	socks5Conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			i := <-rngchan
			reqchan[i] <- 0
			resp := <-respchan[i]
			if resp.err != nil {
				return nil, resp.err
			}
			return resp.client.Dial("tcp", addr)
		},
		Resolver: &DummyResolver{},
	}

	server, err := socks5.New(socks5Conf)
	if err != nil {
		panic(err)
	}

	log.Printf("socks5 server on %s\n", *listenaddr)
	if err := server.ListenAndServe("tcp", *listenaddr); err != nil {
		panic(err)
	}
}
