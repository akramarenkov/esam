/*
  ESAM - Elementary SSH accounts management
  Copyright (C) 2020 Aleksandr Kramarenko akramarenkov@yandex.ru

  This file is part of ESAM.

  ESAM is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  ESAM is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ESAM.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

import (
	"github.com/akramarenkov/esam/src/caches"
	"github.com/akramarenkov/esam/src/certs"
	"github.com/akramarenkov/esam/src/data"
	"github.com/akramarenkov/esam/src/keysconv"
	"github.com/akramarenkov/esam/src/login"
	"github.com/akramarenkov/esam/src/misc"
	"github.com/akramarenkov/esam/src/netapi"
	"github.com/akramarenkov/esam/src/netmsg"
	"github.com/akramarenkov/esam/src/opts"
	"github.com/akramarenkov/esam/src/opts2"
	"github.com/akramarenkov/esam/src/parallel"
	"github.com/akramarenkov/esam/src/passwd"
	"github.com/akramarenkov/esam/src/requests"
	"github.com/akramarenkov/esam/src/types"
	"github.com/akramarenkov/esam/src/ui"
)

import (
	"github.com/mattn/go-isatty"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
	"gopkg.in/yaml.v3"
)

const (
	AppDescription = "ESAM (Elementary SSH accounts management) Client"
	AppVersion     = "0.2"
)

const (
	workingDir      = "${HOME}/.esamc"
	udsName         = "esamc.socket"
	cacheFilePrefix = "esamc-cache"
	cacheFileExt    = ".json"
)

func main() {
	var (
		err error
		app *cli.App
	)

	log.SetFormatter(&log.JSONFormatter{})

	syscall.Umask(0077)
	syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)

	app = cli.NewApp()
	app.Usage = AppDescription
	app.Version = AppVersion
	app.EnableBashCompletion = true

	loginFlags := []cli.Flag{
		&cli.StringFlag{
			Name:  "config",
			Value: "",
			Usage: "path to the configuration file",
		},
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "esam-key",
				Value: "",
				Usage: "path to the private key file",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dir-addr",
				Value: "",
				Usage: "address of connection to Director",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dir-port",
				Value: "",
				Usage: "port of connection to Director",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "tls-ca-cert",
				Value: "",
				Usage: "path to the CA certificate file of the signatory of the Director TLS certificate",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "verify-key",
				Value: "",
				Usage: "path to the public key file used by the Client to verify the authenticity of data received from the Director",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "uds-path",
				Value: path.Join(workingDir, udsName),
				Usage: "path to the Unix socket used to interact with the authenticated Client",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "cache-dir",
				Value: workingDir,
				Usage: "path to the directory with data cache",
			}),
	}

	app.Commands = []*cli.Command{
		{
			Name:         "gen-key",
			Usage:        "Generate a pair of private and public keys used to authenticate the user with the Director",
			Action:       genKeyHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "esam-key",
					Value: "",
					Usage: "path to the private key file",
				},
				&cli.StringFlag{
					Name:  "esam-pub-key",
					Value: "",
					Usage: "path to the public key file",
				},
			},
		},
		{
			Name:         "send-access-req",
			Usage:        "Send an access request",
			Action:       sendAccessReqHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "esam-pub-key",
					Value: "",
					Usage: "path to the public key file",
				},
				&cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "desired account name",
				},
				&cli.StringFlag{
					Name:  "dir-addr",
					Value: "",
					Usage: "address of connection to Director",
				},
				&cli.StringFlag{
					Name:  "dir-port",
					Value: "",
					Usage: "port of connection to Director",
				},
				&cli.StringFlag{
					Name:  "tls-ca-cert",
					Value: "",
					Usage: "path to the CA certificate file of the signatory of the Director TLS certificate",
				},
				&cli.StringFlag{
					Name:  "secret",
					Value: "",
					Usage: "random sequence used for simple authentication when sending an access request",
				},
			},
		},
		{
			Name:         "login",
			Usage:        "Authenticate with the Director",
			Action:       loginHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Before:       altsrc.InitInputSourceWithContext(loginFlags, altsrc.NewYamlSourceFromFlagFunc("config")),
			Flags:        loginFlags,
		},
		{
			Name:         "ssh",
			Usage:        "Connect to the managed node via SSH (auto completion is works)",
			Action:       sshHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
			},
		},
		{
			Name:         "list-access-reqs",
			Usage:        "List access requests",
			Action:       listAccessReqHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "subject",
					Value: "",
					Usage: "output requests only with the specified type of the request subject",
				},
				&cli.BoolFlag{
					Name:  "json",
					Value: false,
					Usage: "output in JSON format",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "del-access-req",
			Usage:        "Delete access request. When adding a user or a managed node with a key that is present in the list of access requests, this request will be deleted automatically",
			Action:       delAccessReqHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "name of the target request subject",
				},
				&cli.StringFlag{
					Name:  "subject",
					Value: "",
					Usage: "filter by type of subject",
				},
				&cli.BoolFlag{
					Name:  "all",
					Value: false,
					Usage: "delete all access requests",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "add-user",
			Usage:        "Add user",
			Action:       addUserHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "manual",
					Value: false,
					Usage: "immediately switch to user add mode without first displaying a list of access requests",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "update-user",
			Usage:        "Update user data",
			Action:       updateUserHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "name of the target user",
				},
				&cli.StringFlag{
					Name:  "sign-key",
					Value: "",
					Usage: "path to the private key file used to sign data instead of the authenticated user key",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "change-password",
			Usage:        "Change the current user password used to elevate privileges on managed nodes",
			Action:       changePasswordHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
			},
		},
		{
			Name:         "list-users",
			Usage:        "List users",
			Action:       listUsersHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "json",
					Value: false,
					Usage: "output in JSON format",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "del-user",
			Usage:        "Delete user",
			Action:       delUserHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "name of the target user",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "add-node",
			Usage:        "Add managed node",
			Action:       addNodeHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "manual",
					Value: false,
					Usage: "immediately switch to node add mode without first displaying a list of access requests",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "update-node",
			Usage:        "Update a managed node data ",
			Action:       updateNodeHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "name of the target node",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "list-nodes",
			Usage:        "List managed nodes",
			Action:       listNodesHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "json",
					Value: false,
					Usage: "output in JSON format",
				},
				&cli.BoolFlag{
					Name:  "no-cache",
					Value: false,
					Usage: "receive data not from the cache of the authenticated Client, but from the Director directly",
				},
				&cli.BoolFlag{
					Name:  "only-trusted",
					Value: false,
					Usage: "display only nodes with trusted (passed authenticity checks) data",
				},
				&cli.BoolFlag{
					Name:  "nullify-esam-pub-key",
					Value: false,
					Usage: "display empty values of the public key of the user used for authentication with the Director (mainly used to reduce output delays)",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "del-node",
			Usage:        "Delete managed node",
			Action:       delNodeHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "name of the target node",
				},
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
				&cli.StringFlag{
					Name:  "dir-uds-path",
					Value: "",
					Usage: "path to the Unix socket used for local management of the Director",
				},
			},
		},
		{
			Name:         "pass-key-password",
			Usage:        "Pass to the running Client a password for the user encrypted private key",
			Action:       passKeyPasswordHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "uds-path",
					Value: path.Join(workingDir, udsName),
					Usage: "path to the Unix socket used to interact with the authenticated Client",
				},
			},
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}

func genKeyHandler(c *cli.Context) error {
	var (
		err      error
		password string
	)

	setPassword, err := ui.AskYesNo("Encrypt key with password?")
	if err != nil {
		ui.PrintError("Failed to read answer", err)
		return err
	}

	if setPassword {
		password, err = ui.ReadPassword("Enter a ESAM key password:", misc.PasswordValidator)
		if err != nil {
			ui.PrintError("Failed to read password", err)
			return err
		}
	}

	err = keysconv.GenAndSaveKeyPair(c.String("esam-key"), c.String("esam-pub-key"), opts.KeySize, password)
	if err != nil {
		ui.PrintError("Failed to generate key pair", err)
		return err
	}

	ui.PrintInfo("ESAM key pair generated successful")

	return nil
}

func sendAccessReqHandler(c *cli.Context) error {
	var (
		err error

		pubKey    *rsa.PublicKey
		pubKeyPem []byte

		tlsConfig tls.Config
		tlsCAPool *x509.CertPool
		dirConn   *tls.Conn

		accessReq data.AccessReq
	)

	pubKey, err = keysconv.LoadPubKeyFromFile(c.String("esam-pub-key"))
	if err != nil {
		ui.PrintError("Failed to load esam-pub-key", err)
		return err
	}

	pubKeyPem, err = keysconv.PubKeyInRSAToPEM(pubKey)
	if err != nil {
		ui.PrintError("Failed to convert esam-pub-key to pem", err)
		return err
	}

	tlsConfig.MinVersion = opts.TLSMinVersion

	if c.String("tls-ca-cert") != "" {
		tlsCAPool, err = certs.LoadCertsBundle(c.String("tls-ca-cert"))
		if err != nil {
			ui.PrintError("Failed to load CA certs bundle", err)
			return err
		}

		tlsConfig.RootCAs = tlsCAPool
	}

	dirConn, err = tls.DialWithDialer(&net.Dialer{Timeout: opts.NetTimeout}, "tcp", c.String("dir-addr")+":"+c.String("dir-port"), &tlsConfig)
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	accessReq.ESAMPubKey = pubKeyPem
	accessReq.Subject = data.AccessReqSubjectUser
	accessReq.Name = c.String("name")

	err = requests.SendAccessReq(dirConn, &accessReq, c.String("secret"), opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to send access request", err)
		return err
	}

	ui.PrintInfo("Access request sent successfully")

	return nil
}

func loginHandler(c *cli.Context) error {
	var (
		err                error
		loginContext       *login.Context
		udsListener        net.Listener
		waitLoops          sync.WaitGroup
		dirConnSettings    *data.DirConnSettings
		nodesCache         caches.NodesAuth
		authUserCache      caches.UserAuth
		esamKeyIsEncrypted bool
		esamKeyPassword    string
	)

	mainCtx, mainCancel := context.WithCancel(context.Background())

	log.Println("Start logging")

	esamKeyIsEncrypted, err = keysconv.KeyIsEncrypted(os.ExpandEnv(c.String("esam-key")))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to determine encryption of key")
		return err
	}

	if esamKeyIsEncrypted {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			esamKeyPassword, err = ui.ReadPassword("Enter a ESAM key password:", nil)
			if err != nil {
				ui.PrintError("Failed to read password", err)
				return err
			}
		} else {
			log.Println("ESAM key encrypted - password required")

			esamKeyPassword, err = udsAskPassword(os.ExpandEnv(c.String("uds-path")))
			if err != nil {
				log.WithFields(log.Fields{"details": err}).Errorln("Failed to read password")
				return err
			}
		}
	}

	loginContext, err = login.MakeContext(os.ExpandEnv(c.String("esam-key")), c.String("dir-addr"), c.String("dir-port"), os.ExpandEnv(c.String("tls-ca-cert")), os.ExpandEnv(c.String("verify-key")), esamKeyPassword)
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to determine login context")
		return err
	}

	dirConnSettings, err = makeDirConnSettings(os.ExpandEnv(c.String("esam-key")), c.String("dir-addr"), c.String("dir-port"), os.ExpandEnv(c.String("tls-ca-cert")), os.ExpandEnv(c.String("verify-key")))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to determine Director connection settings")
		return err
	}

	udsListener, err = net.Listen("unix", os.ExpandEnv(c.String("uds-path")))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to allocate Unix network listener")
		return err
	}

	err = nodesCache.Init(path.Join(os.ExpandEnv(c.String("cache-dir")), cacheFilePrefix+"-nodes"+cacheFileExt))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to init nodes cache")
		return err
	}

	err = authUserCache.Init(path.Join(os.ExpandEnv(c.String("cache-dir")), cacheFilePrefix+"-user"+cacheFileExt))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to init auth user cache")
		return err
	}

	err = nodesCache.FromFile()
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to load cache file")
	}

	err = authUserCache.FromFile()
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to load cache file")
	}

	waitLoops.Add(2)

	go udsLoop(mainCtx, udsListener, dirConnSettings, &authUserCache, &nodesCache, &waitLoops)
	go dirConnLoop(mainCtx, loginContext, &authUserCache, &nodesCache, &waitLoops)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	signalReceiver := <-signalChan
	log.Printf("Received signal '%v' - terminating", signalReceiver)

	mainCancel()

	udsListener.Close()

	waitLoops.Wait()

	log.Println("Stop logging")

	return nil
}

func udsAskPassword(udsPath string) (string, error) {
	var (
		err           error
		password      string
		udsListener   net.Listener
		udsConn       net.Conn
		onceConnClose sync.Once
	)

	ctx, cancel := context.WithCancel(context.Background())

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	freeResources := func() {
		closeConn := func() {
			udsListener.Close()
		}

		onceConnClose.Do(closeConn)
		cancel()
		signal.Reset(os.Interrupt, syscall.SIGTERM)
	}

	udsListener, err = net.Listen("unix", udsPath)
	if err != nil {
		return "", err
	}
	defer freeResources()

	go func() {
		<-signalChan
		freeResources()
	}()

	udsConnHandler := func(conn net.Conn) (string, error) {
		defer conn.Close()

		var (
			err      error
			password string

			msgIn       []byte
			msgOut      []byte
			msgInHeader netapi.MsgHeader
		)

		sendErrorReply := func(reason string) {
			var (
				err error
			)

			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusFailed, reason})
			if err == nil {
				_, _ = netmsg.Send(conn, msgOut, opts.NetTimeout)
			}
		}

		sendSuccessfulReply := func() {
			var (
				err error
			)

			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusSuccessful, netapi.ReqResultReasonEmpty})
			if err == nil {
				_, _ = netmsg.Send(conn, msgOut, opts.NetTimeout)
			}
		}

		for {
			select {
			case <-ctx.Done():
				{
					return "", errors.New("Interrupted")
				}

			default:
				{
					msgIn, err = netmsg.Recv(conn, opts.NetTimeout)
					if err != nil {
						if netmsg.IsTimeout(err) {
							continue
						}

						if netmsg.IsEOF(err) {
							return "", errors.New("Connection closed")
						}

						return "", err
					}

					err = netapi.ParseMsgHeader(msgIn, &msgInHeader)
					if err != nil {
						return "", err
					}

					switch msgInHeader.Type {
					case netapi.MsgTypeRequest:
						{
							switch msgInHeader.SubType {
							case netapi.ReqTypePassKeyPassword:
								{
									password, err = netapi.ParseReqPassKeyPassword(msgIn)
									if err != nil {
										sendErrorReply(netapi.ReqResultReasonInvalidInputData)
										return "", err
									}

									sendSuccessfulReply()

									return password, nil
								}

							default:
								{
									sendErrorReply(netapi.ReqResultReasonKeyPasswordRequired)
								}
							}
						}

					default:
						{
							return "", errors.New("Unexpected message received")
						}
					}
				}
			}
		}

		return "", errors.New("Unexpected behavior")
	}

	for {
		select {
		case <-ctx.Done():
			{
				return "", errors.New("Interrupted")
			}

		default:
			{
				udsConn, err = udsListener.Accept()
				if err != nil {
					if netmsg.IsTemporary(err) {
						log.WithFields(log.Fields{"details": err}).Errorln("Failed to accept UDS connection")
					}
				} else {
					password, err = udsConnHandler(udsConn)
					if err != nil {
						log.WithFields(log.Fields{"details": err}).Errorln("Key password required")
					} else {
						return password, nil
					}
				}
			}
		}
	}

	return "", errors.New("Unexpected behavior")
}

func udsLoop(ctx context.Context, listener net.Listener, dirConnSettings *data.DirConnSettings, authUserCache *caches.UserAuth, nodesCache *caches.NodesAuth, wait *sync.WaitGroup) {
	defer wait.Done()

	var (
		err      error
		udsConn  net.Conn
		waitConn sync.WaitGroup
	)
	for {
		select {
		case <-ctx.Done():
			{
				waitConn.Wait()
				return
			}

		default:
			{
				udsConn, err = listener.Accept()
				if err != nil {
					if netmsg.IsTemporary(err) {
						log.WithFields(log.Fields{"details": err}).Errorln("Failed to accept UDS connection")
					}
				} else {
					waitConn.Add(1)
					go udsConnHandler(ctx, udsConn, dirConnSettings, authUserCache, nodesCache, &waitConn)
				}
			}
		}
	}

	return
}

func udsConnHandler(ctx context.Context, conn net.Conn, dirConnSettings *data.DirConnSettings, authUserCache *caches.UserAuth, nodesCache *caches.NodesAuth, wait *sync.WaitGroup) {
	defer conn.Close()
	defer wait.Done()

	var (
		err error

		msgIn       []byte
		msgOut      []byte
		msgInHeader netapi.MsgHeader

		requireSendErrorReply bool
		reasonSendErrorReply  string
	)

	sendErrorReply := func() {
		var (
			err error
		)

		if requireSendErrorReply {
			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusFailed, reasonSendErrorReply})
			if err == nil {
				_, _ = netmsg.Send(conn, msgOut, opts.NetTimeout)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			{
				return
			}

		default:
			{
				requireSendErrorReply = true
				reasonSendErrorReply = netapi.ReqResultReasonInternalError

				msgIn, err = netmsg.Recv(conn, opts.NetTimeout)
				if err != nil {
					if netmsg.IsTimeout(err) {
						//log.Println("Timeout interrupt")
						continue
					} else {
						if netmsg.IsEOF(err) {
							//log.Println("Connection closed")
						} else {
							log.WithFields(log.Fields{"details": err}).Errorln("Failed to receive message")
						}
						return
					}
				}

				err = netapi.ParseMsgHeader(msgIn, &msgInHeader)
				if err != nil {
					log.WithFields(log.Fields{"details": err}).Errorln("Failed to parse message header")
					continue
				}

				switch msgInHeader.Type {
				case netapi.MsgTypeRequest:
					{
						switch msgInHeader.SubType {
						case netapi.ReqTypeFindInNodesCache:
							{
								processFindInNodesCache := func() error {
									defer sendErrorReply()

									var (
										nodeFilter data.NodeAuth
										nodesList  []data.NodeAuth
										fullMatch  bool
									)

									err = netapi.ParseReqFindInNodesCache(msgIn, &nodeFilter, &fullMatch)
									if err != nil {
										return err
									}

									nodesCache.RLock()
									nodesList = nodesCache.Get()

									nodesList, _ = filterNodeAuthList(nodesList, &nodeFilter, fullMatch)

									msgOut, err = netapi.BuildRepFindInNodesCache(nodesList)
									nodesCache.RUnlock()

									if err != nil {
										return err
									}

									requireSendErrorReply = false

									_, err = netmsg.Send(conn, msgOut, opts.NetTimeout)
									if err != nil {
										return err
									}

									return nil
								}

								err = processFindInNodesCache()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
								}

								continue
							}

						case netapi.ReqTypeGetDirConnSettings:
							{
								processGetDirConnSettings := func() error {
									defer sendErrorReply()

									var (
										err error
									)

									msgOut, err = netapi.BuildRepGetDirConnSettings(dirConnSettings)
									if err != nil {
										return err
									}

									requireSendErrorReply = false

									_, err = netmsg.Send(conn, msgOut, opts.NetTimeout)
									if err != nil {
										return err
									}

									return nil
								}

								err = processGetDirConnSettings()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
								}

								continue
							}

						case netapi.ReqTypeGetAuthUserData:
							{
								processGetAuthUserData := func() error {
									defer sendErrorReply()

									var (
										err          error
										authUserData data.UserAuth
									)

									authUserData = authUserCache.Get()
									msgOut, err = netapi.BuildRepGetAuthUserData(&authUserData)
									if err != nil {
										return err
									}

									requireSendErrorReply = false

									_, err = netmsg.Send(conn, msgOut, opts.NetTimeout)
									if err != nil {
										return err
									}

									return nil
								}

								err = processGetAuthUserData()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
								}

								continue
							}

						default:
							{
								log.Errorln("Unsupported at this stage request was received")

								reasonSendErrorReply = netapi.ReqResultReasonUnsupportedReq
								sendErrorReply()

								continue
							}
						}
					}

				case netapi.MsgTypeReply:
					{
						log.Errorln("Message type 'reply' is not expected at this stage")

						msgOut, err = netapi.BuildUnsupportedMsg()
						if err == nil {
							_, _ = netmsg.Send(conn, msgOut, opts.NetTimeout)
						}

						continue
					}

				case netapi.MsgTypeNotice:
					{
						log.Errorln("Message type 'notice' is not expected at this stage")

						msgOut, err = netapi.BuildUnsupportedMsg()
						if err == nil {
							_, _ = netmsg.Send(conn, msgOut, opts.NetTimeout)
						}

						continue
					}

				default:
					{
						log.Errorln("Unsupported message was received")

						msgOut, err = netapi.BuildUnsupportedMsg()
						if err == nil {
							_, _ = netmsg.Send(conn, msgOut, opts.NetTimeout)
						}

						continue
					}
				}
			}
		}
	}

	log.Errorln("Unknown error at the beginning of the connection process")

	return
}

func dirConnLoop(ctx context.Context, loginContext *login.Context, authUserCache *caches.UserAuth, nodesCache *caches.NodesAuth, wait *sync.WaitGroup) {
	defer wait.Done()

	var (
		err                   error
		dirConn               *tls.Conn
		dirConnAllocated      bool
		updateNodesCacheTimer <-chan time.Time
		noMsgTimer            <-chan time.Time
		noopTimer             <-chan time.Time

		usersListDB []data.UserDB
		nodesListDB []data.NodeDB
	)

	freeLoopResources := func() {
		if dirConnAllocated {
			dirConn.Close()
			dirConnAllocated = false
		}
	}

	defer freeLoopResources()

	for {
		select {
		case <-ctx.Done():
			{
				return
			}

		default:
			{
				freeLoopResources()

				dirConn, err = tls.DialWithDialer(&net.Dialer{Timeout: opts.NetTimeout}, "tcp", loginContext.DirAddr+":"+loginContext.DirPort, &loginContext.TLSConfig)
				if err != nil {
					log.WithFields(log.Fields{"details": err}).Errorln("Failed to connect to Director")
					break
				}

				dirConnAllocated = true

				err = requests.Auth(dirConn, &loginContext.ESAMPubKey, loginContext.Key, false, opts.NetTimeout)
				if err != nil {
					log.WithFields(log.Fields{"details": err}).Errorln("Login failed")
					break
				}

				log.Println("Login successful")

				noMsgTimer = time.After(opts.NoMsgThresholdTime)
				noopTimer = time.After(opts.NoopNoticePeriod)
				updateNodesCacheTimer = time.After(0)
				time.Sleep(1 * time.Millisecond)

			authLoop:
				for {
					var (
						msgIn       []byte
						msgOut      []byte
						msgInHeader netapi.MsgHeader
					)
					sendReqListUsers := func(netTimeout time.Duration) error {
						var (
							err        error
							userFilter data.User
						)

						msgOut, err = netapi.BuildReqListUsers(&userFilter)
						if err != nil {
							return err
						}

						_, err = netmsg.Send(dirConn, msgOut, netTimeout)
						if err != nil {
							return err
						}

						return nil
					}

					sendReqListNodes := func(netTimeout time.Duration) error {
						var (
							err        error
							nodeFilter data.Node
						)

						msgOut, err = netapi.BuildReqListNodes(&nodeFilter)
						if err != nil {
							return err
						}

						_, err = netmsg.Send(dirConn, msgOut, netTimeout)
						if err != nil {
							return err
						}

						return nil
					}

					sendNoop := func(netTimeout time.Duration) error {
						var (
							err error
						)

						msgOut, err = netapi.BuildNotice(netapi.NoticeTypeNoop)
						if err != nil {
							return err
						}

						_, err = netmsg.Send(dirConn, msgOut, netTimeout)
						if err != nil {
							return err
						}

						return nil
					}

					updateNodesCache := func() {
						if len(nodesListDB) > 0 && len(usersListDB) > 0 {
							log.Println("Update nodes cache")

							updateNodesCacheTimer = time.After(opts.UpdateNodesCachePeriod)

							err = nodesCache.Update(nodesListDB, usersListDB, &loginContext.VerifyKey, opts.CPUUtilizationFactor)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to update nodes cache")
							} else {
								log.Println("Nodes cache update successful")
								log.Println("Save nodes cache to file")

								err = nodesCache.ToFile()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Failed to save nodes cache to file")
								} else {
									log.Println("Nodes cache successfully saved to file")
								}
							}
						}
					}

					select {
					case <-ctx.Done():
						{
							return
						}

					case <-noMsgTimer:
						{
							log.WithFields(log.Fields{"details": err}).Errorln("Messages were missing more than the threshold time - reconnect")
							break authLoop
						}

					case <-noopTimer:
						{
							noopTimer = time.After(opts.NoopNoticePeriod)

							err = sendNoop(opts.NetTimeout)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to send noop notice")
								break authLoop
							}
						}

					case <-updateNodesCacheTimer:
						{
							updateNodesCacheTimer = time.After(opts.UpdateNodesCachePeriod)

							log.Println("Send requests to refresh nodes cache")

							err = sendReqListUsers(opts.NetTimeout)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to send request to get list of users")
								break authLoop
							}

							err = sendReqListNodes(opts.NetTimeout)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to send request to get list of users")
								break authLoop
							}

							log.Println("Successfully sent nodes cache update requests")

							usersListDB = []data.UserDB{}
							nodesListDB = []data.NodeDB{}
						}

					default:
						{
							msgIn, err = netmsg.Recv(dirConn, opts.NetTimeout)
							if err != nil {
								if netmsg.IsTimeout(err) {
									//log.Println("Timeout interrupt")
									continue
								} else {
									if netmsg.IsEOF(err) {
										//log.Println("Connection closed")
									} else {
										log.WithFields(log.Fields{"details": err}).Errorln("Failed to receive message")
									}
									break authLoop
								}
							}

							err = netapi.ParseMsgHeader(msgIn, &msgInHeader)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to parse message header")
								break authLoop
							}

							switch msgInHeader.Type {
							case netapi.MsgTypeReply:
								{
									noMsgTimer = time.After(opts.NoMsgThresholdTime)

									switch msgInHeader.SubType {
									case netapi.ReqTypeListUsers:
										{
											usersListDB, err = netapi.ParseRepListUsers(msgIn)
											if err != nil {
												break authLoop
											}

											updateNodesCache()

											log.Println("Update auth user cache")

											err = authUserCache.Update(usersListDB, &loginContext.ESAMPubKey, &loginContext.VerifyKey)
											if err != nil {
												log.WithFields(log.Fields{"details": err}).Errorln("Failed to update auth user data")
											} else {
												log.Println("Auth user cache update successful")
												log.Println("Save auth user cache to file")

												err = authUserCache.ToFile()
												if err != nil {
													log.WithFields(log.Fields{"details": err}).Errorln("Failed to save auth user cache to file")
												} else {
													log.Println("Auth user cache successfully saved to file")
												}
											}
										}

									case netapi.ReqTypeListNodes:
										{
											nodesListDB, err = netapi.ParseRepListNodes(msgIn)
											if err != nil {
												break authLoop
											}

											updateNodesCache()
										}

									default:
										{
											log.WithFields(log.Fields{"details": err}).Errorln("Unsupported at this stage reply was received")
											continue
										}
									}
								}

							case netapi.MsgTypeNotice:
								{
									noMsgTimer = time.After(opts.NoMsgThresholdTime)

									switch msgInHeader.SubType {
									case netapi.NoticeTypeNoop:
										{
											//log.Println("NOOP")
											continue
										}

									case netapi.NoticeTypeUpdatedUsers:
										{
											log.Println("Send requests to get nodes cache")

											err = sendReqListUsers(opts.NetTimeout)
											if err != nil {
												log.WithFields(log.Fields{"details": err}).Errorln("Failed to send request to get list of users")
												break authLoop
											}

											log.Println("Successfully sent requests to get nodes cache")
										}

									case netapi.NoticeTypeUpdatedNodes:
										{
											log.Println("Send requests to get nodes cache")

											err = sendReqListNodes(opts.NetTimeout)
											if err != nil {
												log.WithFields(log.Fields{"details": err}).Errorln("Failed to send request to get list of nodes")
												break authLoop
											}

											log.Println("Successfully sent requests to get nodes cache")
										}

									default:
										{
											log.WithFields(log.Fields{"details": err}).Errorln("Unsupported at this stage notice was received")
											continue
										}
									}
								}

							default:
								{
									log.WithFields(log.Fields{"details": err}).Errorln("Unsupported message was received")
									continue
								}
							}
						}
					}
				}
			}
		}

		time.Sleep(opts.ReconnectPause)
	}

	return
}

func sshHandler(c *cli.Context) error {
	var (
		err          error
		clientConn   net.Conn
		authUserData data.UserAuth
		nodeFilter   data.NodeAuth
		nodesList    []data.NodeAuth
		selectedNode data.NodeAuth
		ssh          *exec.Cmd
	)

	if c.Args().Len() > 0 {
		nodeFilter.Name = c.Args().Get(0)
	}

	clientConn, err = net.DialTimeout("unix", os.ExpandEnv(c.String("uds-path")), opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to connect to authenticated Client", err)
		return err
	}
	defer clientConn.Close()

	err = requests.GetAuthUserData(clientConn, &authUserData, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get user data", err)
		return err
	}

	nodesList, err = requests.FindInNodesCache(clientConn, &nodeFilter, true, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get nodes list", err)
		return err
	}

	if len(nodesList) == 0 {
		nodesList, err = requests.FindInNodesCache(clientConn, &nodeFilter, false, opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to get nodes list", err)
			return err
		}
	}

	if len(nodesList) == 0 {
		err = errors.New("Nodes list is empty")
		ui.PrintError("Failed to get nodes list", err)
		return err
	}

	if len(nodesList) == 1 {
		selectedNode = nodesList[0]
	}

	if len(nodesList) > 1 {
		err = ui.Select("Please select node:", nodesList, &selectedNode, opts.UIPageSize)
		if err != nil {
			ui.PrintError("Failed to select node", err)
			return err
		}
	}

	if selectedNode.Equal(&data.Node{}) {
		return nil
	}

	ssh = exec.Command("ssh", authUserData.Name+"@"+selectedNode.SSHAddr, "-p", selectedNode.SSHPort)
	ssh.Stdin = os.Stdin
	ssh.Stdout = os.Stdout
	ssh.Stderr = os.Stderr
	err = ssh.Run()
	if err != nil {
		ui.PrintError("Failed to run ssh client", err)
	}

	return nil
}

func listAccessReqHandler(c *cli.Context) error {
	var (
		err error

		dirConn         net.Conn
		accessReqFilter data.AccessReqDB
		accessReqsList  []data.AccessReqDB

		out []byte
	)

	dirConn, _, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	accessReqFilter.Subject = c.String("subject")

	err = accessReqFilter.Normalize(data.ToleratesEmptyFieldsYes)
	if err != nil {
		ui.PrintError("Failed to normalize access requests filter", err)
		return err
	}

	err = accessReqFilter.Test(data.ToleratesEmptyFieldsYes)
	if err != nil {
		ui.PrintError("Failed to test access requests filter", err)
		return err
	}

	accessReqsList, err = requests.ListAccessReqs(dirConn, &accessReqFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get list of access requests", err)
		return err
	}

	if c.Bool("json") {
		out, err = json.MarshalIndent(accessReqsList, "", " ")
		if err != nil {
			ui.PrintError("Failed to marshal out to json", err)
			return err
		}
	} else {
		out, err = yaml.Marshal(accessReqsList)
		if err != nil {
			ui.PrintError("Failed to marshal out to yaml", err)
			return err
		}
	}

	fmt.Printf("%v", string(out))

	return nil
}

func delAccessReqHandler(c *cli.Context) error {
	var (
		err error

		dirConn           net.Conn
		accessReqFilter   data.AccessReqDB
		foundAccessReqs   []data.AccessReqDB
		selectedAccessReq data.AccessReqDB
	)

	dirConn, _, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	if !c.Bool("all") {
		accessReqFilter.Name = c.String("name")
		accessReqFilter.Subject = c.String("subject")
	}

	foundAccessReqs, err = requests.ListAccessReqs(dirConn, &accessReqFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get access request data", err)
		return err
	}

	if !c.Bool("all") {
		if len(foundAccessReqs) == 1 {
			selectedAccessReq = foundAccessReqs[0]
			fmt.Printf("%v\n", selectedAccessReq)
		}

		if len(foundAccessReqs) > 1 {
			err = ui.Select("Please select access request:", foundAccessReqs, &selectedAccessReq, opts.UIPageSize)
			if err != nil {
				ui.PrintError("Failed to select access request", err)
				return err
			}
		}

		if selectedAccessReq.Equal(&data.AccessReqDB{}) {
			return nil
		}

		delAccessReq, err := ui.AskYesNo("Delete access request?")
		if err != nil {
			ui.PrintError("Failed to read answer", err)
			return err
		}

		if delAccessReq {
			err = requests.DelAccessReq(dirConn, &selectedAccessReq.ESAMPubKey, opts.NetTimeout)
			if err != nil {
				ui.PrintError("Failed to delete access request", err)
				return err
			} else {
				ui.PrintInfo("Access request deleted successfully")
			}
		}
	} else {
		delAllAccessReq, err := ui.AskYesNo("Delete all access requests? (" + strconv.FormatInt(int64(len(foundAccessReqs)), 10) + ")")
		if err != nil {
			ui.PrintError("Failed to read answer", err)
			return err
		}

		if delAllAccessReq {
			for index := range foundAccessReqs {
				err = requests.DelAccessReq(dirConn, &foundAccessReqs[index].ESAMPubKey, opts.NetTimeout)
				if err != nil {
					ui.PrintError("Failed to delete access request", err)
					return err
				} else {
					ui.PrintInfo("Access request deleted successfully")
					//fmt.Printf("%v\n", foundAccessReqs[index])
				}
			}
		}
	}

	return nil
}

func addUserHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		loginContext *login.Context
		newUser      data.UserDB
	)

	dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	newUser.User.Template()

	if !c.Bool("manual") {
		var (
			accessReqFilter   data.AccessReqDB
			accessReqsList    []data.AccessReqDB
			accessReqSelected data.AccessReqDB
		)

		accessReqSelected.ESAMPubKey = newUser.ESAMPubKey

		accessReqFilter.Subject = data.AccessReqSubjectUser

		accessReqsList, err = requests.ListAccessReqs(dirConn, &accessReqFilter, opts.NetTimeout)
		/*if err != nil {
		  ui.PrintError("Failed to get list of access requests", err)
		  return err
		}*/

		if len(accessReqsList) > 0 {
			err = ui.Select("Please select access request:", accessReqsList, &accessReqSelected, opts.UIPageSize)
			if err != nil {
				ui.PrintError("Failed to select list of access requests", err)
				return err
			}

			newUser.ESAMPubKey = accessReqSelected.ESAMPubKey
			newUser.Name = accessReqSelected.Name
		} else {
			ui.PrintInfo("List of access requests is empty")
		}
	}

	setPassword, err := ui.AskYesNo("Set user password?")
	if err != nil {
		ui.PrintError("Failed to read answer", err)
		return err
	}

	if setPassword {
		var (
			userPassword string
		)

		userPassword, err = ui.ReadPassword("Enter a password:", misc.PasswordValidator)
		if err != nil {
			ui.PrintError("Failed to read password", err)
			return err
		}

		newUser.PasswordHash, err = passwd.CalcHash(userPassword, opts2.PasswdHashAlgo)
		if err != nil {
			ui.PrintError("Failed to hashing password", err)
			return err
		}
	}

	err = ui.Edit("Please edit new user data:", &newUser.User)
	if err != nil {
		ui.PrintError("Failed to edit user data", err)
		return err
	}

	err = newUser.Normalize()
	if err != nil {
		ui.PrintError("Failed to normalize user data", err)
		return err
	}

	if loginContext != nil {
		err = newUser.Sign(loginContext.Key, nil)
		if err != nil {
			ui.PrintError("Failed to sign new user data", err)
			return err
		}

		err = newUser.Verify(nil)
		if err != nil {
			ui.PrintError("Failed to verify sign of new user data", err)
			return err
		}
	}

	err = requests.AddUser(dirConn, &newUser, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to add user", err)
		return err
	} else {
		ui.PrintInfo("User added successfully")
	}

	return nil
}

func updateUserHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		loginContext *login.Context

		userFilter   data.User
		foundUsers   []data.UserDB
		selectedUser data.UserDB
		updatedUser  data.UserDB

		altSignKey *rsa.PrivateKey
	)

	dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	userFilter.Name = c.String("name")

	foundUsers, err = requests.ListUsers(dirConn, &userFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get user data", err)
		return err
	}

	if len(foundUsers) == 1 {
		selectedUser = foundUsers[0]
	}

	if len(foundUsers) > 1 {
		err = ui.Select("Please select user:", foundUsers, &selectedUser, opts.UIPageSize)
		if err != nil {
			ui.PrintError("Failed to select user", err)
			return err
		}
	}

	if selectedUser.Equal(&data.UserDB{}) {
		return nil
	}

	updatedUserTmp, err := selectedUser.Copy()
	if err != nil {
		ui.PrintError("Failed to copy user data", err)
		return err
	}

	updatedUser.User = updatedUserTmp.User

	setPassword, err := ui.AskYesNo("Set user password?")
	if err != nil {
		ui.PrintError("Failed to read answer", err)
		return err
	}

	if setPassword {
		var (
			userPassword string
		)

		userPassword, err = ui.ReadPassword("Enter a password:", misc.PasswordValidator)
		if err != nil {
			ui.PrintError("Failed to read password", err)
			return err
		}

		updatedUser.PasswordHash, err = passwd.CalcHash(userPassword, opts2.PasswdHashAlgo)
		if err != nil {
			ui.PrintError("Failed to hashing password", err)
			return err
		}
	}

	err = ui.Edit("Please edit user data:", &updatedUser.User)
	if err != nil {
		ui.PrintError("Failed to edit user data", err)
		return err
	}

	if updatedUser.User.Equal(&selectedUser.User) {
		reSign, err := ui.AskYesNo("User data has not been changed. It data will be re-signed or cleared of sign. Continue?")
		if err != nil {
			ui.PrintError("Failed to read answer", err)
			return err
		}

		if !reSign {
			ui.PrintInfo("You refused to continue")
			return nil
		}
	}

	err = updatedUser.Normalize()
	if err != nil {
		ui.PrintError("Failed to normalize user data", err)
		return err
	}

	if c.String("sign-key") != "" {
		var (
			signKeyIsEncrypted bool
			signKeyPassword    string
		)

		signKeyIsEncrypted, err = keysconv.KeyIsEncrypted(c.String("sign-key"))
		if err != nil {
			ui.PrintError("Failed to determine encryption of key", err)
			return err
		}

		if signKeyIsEncrypted {
			signKeyPassword, err = ui.ReadPassword("Enter a sign key password:", nil)
			if err != nil {
				ui.PrintError("Failed to read password", err)
				return err
			}
		}

		altSignKey, err = keysconv.LoadKeyFromFile(c.String("sign-key"), signKeyPassword)
		if err != nil {
			ui.PrintError("Failed to load sign-key", err)
			return err
		}
	}

	if loginContext != nil || altSignKey != nil {
		if altSignKey != nil {
			err = updatedUser.Sign(altSignKey, nil)
			if err != nil {
				ui.PrintError("Failed to sign user data with sign-key", err)
				return err
			}
		} else {
			err = updatedUser.Sign(loginContext.Key, nil)
			if err != nil {
				ui.PrintError("Failed to sign user data", err)
				return err
			}
		}

		err = updatedUser.Verify(nil)
		if err != nil {
			ui.PrintError("Failed to verify sign user data", err)
			return err
		}
	}

	err = requests.UpdateUser(dirConn, &selectedUser.ESAMPubKey, &updatedUser, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to update user", err)
		return err
	} else {
		ui.PrintInfo("User update successfully")
	}

	return nil
}

func changePasswordHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		loginContext *login.Context
		userPassword string
		userData     data.UserDB
	)

	dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), "")
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	if loginContext == nil {
		err = errors.New("Authentication required")
		ui.PrintError("To perform this operation, you must authenticate with the Director", err)
		return err
	}

	userPassword, err = ui.ReadPassword("Enter a password:", misc.PasswordValidator)
	if err != nil {
		ui.PrintError("Failed to read password", err)
		return err
	}

	userData.User.PasswordHash, err = passwd.CalcHash(userPassword, opts2.PasswdHashAlgo)
	if err != nil {
		ui.PrintError("Failed to hashing password", err)
		return err
	}

	userData.User.ESAMPubKey = loginContext.ESAMPubKey

	err = userData.Sign(loginContext.Key, map[string]bool{"PasswordHash": true})
	if err != nil {
		ui.PrintError("Failed to sign user data", err)
		return err
	}

	err = requests.ChangePassword(dirConn, userPassword, userData.User.PasswordHash, userData.UserSign.PasswordHashSign, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to change password", err)
		return err
	} else {
		ui.PrintInfo("Password successfully changed")
	}

	return nil
}

func listUsersHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		loginContext *login.Context

		userFilter  data.User
		usersListDB []data.UserDB
		usersList   []data.UserAuth

		out []byte
	)

	dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	usersListDB, err = requests.ListUsers(dirConn, &userFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get user data", err)
		return err
	}

	if loginContext != nil {
		usersList, err = parallel.MakeUserAuthList(usersListDB, &loginContext.VerifyKey, opts.CPUUtilizationFactor)
	} else {
		usersList, err = parallel.MakeUserAuthList(usersListDB, nil, opts.CPUUtilizationFactor)
	}
	if err != nil {
		ui.PrintError("Failed to process users auth list", err)
		return err
	}

	if c.Bool("json") {
		out, err = json.MarshalIndent(usersList, "", " ")
		if err != nil {
			ui.PrintError("Failed to marshal out to json", err)
			return err
		}
	} else {
		out, err = yaml.Marshal(usersList)
		if err != nil {
			ui.PrintError("Failed to marshal out to yaml", err)
			return err
		}
	}

	fmt.Printf("%v", string(out))

	return nil
}

func delUserHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		userFilter   data.User
		foundUsers   []data.UserDB
		selectedUser data.UserDB
	)

	dirConn, _, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	userFilter.Name = c.String("name")

	foundUsers, err = requests.ListUsers(dirConn, &userFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get user data", err)
		return err
	}

	if len(foundUsers) == 1 {
		selectedUser = foundUsers[0]
		fmt.Printf("%v\n", selectedUser)
	}

	if len(foundUsers) > 1 {
		err = ui.Select("Please select user:", foundUsers, &selectedUser, opts.UIPageSize)
		if err != nil {
			ui.PrintError("Failed to select user", err)
			return err
		}
	}

	if selectedUser.Equal(&data.UserDB{}) {
		return nil
	}

	delUser, err := ui.AskYesNo("Delete user?")
	if err != nil {
		ui.PrintError("Failed to read answer", err)
		return err
	}

	if delUser {
		err = requests.DelUser(dirConn, &selectedUser.ESAMPubKey, opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to delete user", err)
			return err
		} else {
			ui.PrintInfo("User deleted successfully")
		}
	}

	return nil
}

func addNodeHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		loginContext *login.Context
		newNode      data.NodeDB
	)

	dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	newNode.Node.Template()

	if !c.Bool("manual") {
		var (
			accessReqFilter   data.AccessReqDB
			accessReqsList    []data.AccessReqDB
			accessReqSelected data.AccessReqDB
		)

		accessReqSelected.ESAMPubKey = newNode.ESAMPubKey

		accessReqFilter.Subject = data.AccessReqSubjectAgent

		accessReqsList, err = requests.ListAccessReqs(dirConn, &accessReqFilter, opts.NetTimeout)
		/*if err != nil {
		  ui.PrintError("Failed to get list of access requests", err)
		  return err
		}*/

		if len(accessReqsList) > 0 {
			err = ui.Select("Please select access request:", accessReqsList, &accessReqSelected, opts.UIPageSize)
			if err != nil {
				ui.PrintError("Failed to select list of access requests", err)
				return err
			}

			newNode.ESAMPubKey = accessReqSelected.ESAMPubKey
			newNode.Name = accessReqSelected.Name
			newNode.SSHAddr = accessReqSelected.Addr
		} else {
			ui.PrintInfo("List of access requests is empty")
		}
	}

	err = ui.Edit("Please edit new node data:", &newNode.Node)
	if err != nil {
		ui.PrintError("Failed to edit node data", err)
		return err
	}

	err = newNode.Normalize()
	if err != nil {
		ui.PrintError("Failed to normalize node data", err)
		return err
	}

	if loginContext != nil {
		err = newNode.Sign(loginContext.Key)
		if err != nil {
			ui.PrintError("Failed to sign new node data", err)
			return err
		}

		err = newNode.Verify()
		if err != nil {
			ui.PrintError("Failed to verify sign of new node data", err)
			return err
		}
	}

	err = requests.AddNode(dirConn, &newNode, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to add node", err)
		return err
	} else {
		ui.PrintInfo("Node added successfully")
	}

	return nil
}

func updateNodeHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		loginContext *login.Context

		nodeFilter   data.Node
		foundNodes   []data.NodeDB
		selectedNode data.NodeDB
		updatedNode  data.NodeDB
	)

	dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	nodeFilter.Name = c.String("name")

	foundNodes, err = requests.ListNodes(dirConn, &nodeFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get node data", err)
		return err
	}

	if len(foundNodes) == 1 {
		selectedNode = foundNodes[0]
	}

	if len(foundNodes) > 1 {
		err = ui.Select("Please select node:", foundNodes, &selectedNode, opts.UIPageSize)
		if err != nil {
			ui.PrintError("Failed to select node", err)
			return err
		}
	}

	if selectedNode.Equal(&data.NodeDB{}) {
		return nil
	}

	updatedNodeTmp, err := selectedNode.Copy()
	if err != nil {
		ui.PrintError("Failed to copy node data", err)
		return err
	}

	updatedNode.Node = updatedNodeTmp.Node

	err = ui.Edit("Please edit node data:", &updatedNode.Node)
	if err != nil {
		ui.PrintError("Failed to edit node data", err)
		return err
	}

	if updatedNode.Node.Equal(&selectedNode.Node) {
		reSign, err := ui.AskYesNo("Node data has not been changed. It data will be re-signed or cleared of sign. Continue?")
		if err != nil {
			ui.PrintError("Failed to read answer", err)
			return err
		}

		if !reSign {
			ui.PrintInfo("You refused to continue")
			return nil
		}
	}

	if loginContext != nil {
		err = updatedNode.Sign(loginContext.Key)
		if err != nil {
			ui.PrintError("Failed to sign node data", err)
			return err
		}

		err = updatedNode.Verify()
		if err != nil {
			ui.PrintError("Failed to verify sign node data", err)
			return err
		}
	}

	err = requests.UpdateNode(dirConn, &selectedNode.ESAMPubKey, &updatedNode, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to update node", err)
		return err
	} else {
		ui.PrintInfo("Node update successfully")
	}

	return nil
}

func listNodesHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		clientConn   net.Conn
		loginContext *login.Context

		nodeFilterAuth data.NodeAuth
		nodesList      []data.NodeAuth

		out []byte
	)

	if c.Args().Len() > 0 {
		nodeFilterAuth.Name = c.Args().Get(0)
	}

	if c.Bool("only-trusted") {
		nodeFilterAuth.TrustedData = types.True
	}

	if c.Bool("no-cache") {
		var (
			nodeFilter  data.Node
			userFilter  data.User
			nodesListDB []data.NodeDB
			usersListDB []data.UserDB
		)

		dirConn, loginContext, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
		if err != nil {
			ui.PrintError("Failed to connect to Director", err)
			return err
		}
		defer dirConn.Close()

		usersListDB, err = requests.ListUsers(dirConn, &userFilter, opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to get users list", err)
			return err
		}

		nodesListDB, err = requests.ListNodes(dirConn, &nodeFilter, opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to get nodes list", err)
			return err
		}

		if loginContext != nil {
			nodesList, err = parallel.MakeNodeAuthList(nodesListDB, usersListDB, &loginContext.VerifyKey, opts.CPUUtilizationFactor)
		} else {
			nodesList, err = parallel.MakeNodeAuthList(nodesListDB, usersListDB, nil, opts.CPUUtilizationFactor)
		}
		if err != nil {
			ui.PrintError("Failed to get nodes auth list", err)
			return err
		}

		nodesList, _ = filterNodeAuthList(nodesList, &nodeFilterAuth, false)
	} else {
		clientConn, err = net.DialTimeout("unix", os.ExpandEnv(c.String("uds-path")), opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to connect to authenticated Client", err)
			return err
		}
		defer clientConn.Close()

		nodesList, err = requests.FindInNodesCache(clientConn, &nodeFilterAuth, false, opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to search in nodes cache", err)
			return err
		}
	}

	if c.Bool("nullify-esam-pub-key") {
		for index := range nodesList {
			nodesList[index].ESAMPubKey = []byte{}
		}
	}

	if c.Bool("json") {
		out, err = json.MarshalIndent(nodesList, "", " ")
		if err != nil {
			ui.PrintError("Failed to marshal out to json", err)
			return err
		}
	} else {
		out, err = yaml.Marshal(nodesList)
		if err != nil {
			ui.PrintError("Failed to marshal out to yaml", err)
			return err
		}
	}

	fmt.Printf("%v", string(out))

	return nil
}

func delNodeHandler(c *cli.Context) error {
	var (
		err error

		dirConn      net.Conn
		nodeFilter   data.Node
		foundNodes   []data.NodeDB
		selectedNode data.NodeDB
	)

	dirConn, _, err = connectToDirectorOnOneTry(c.String("uds-path"), c.String("dir-uds-path"))
	if err != nil {
		ui.PrintError("Failed to connect to Director", err)
		return err
	}
	defer dirConn.Close()

	nodeFilter.Name = c.String("name")

	foundNodes, err = requests.ListNodes(dirConn, &nodeFilter, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to get node data", err)
		return err
	}

	if len(foundNodes) == 1 {
		selectedNode = foundNodes[0]
		fmt.Printf("%v\n", selectedNode)
	}

	if len(foundNodes) > 1 {
		err = ui.Select("Please select node:", foundNodes, &selectedNode, opts.UIPageSize)
		if err != nil {
			ui.PrintError("Failed to select node", err)
			return err
		}
	}

	if selectedNode.Equal(&data.NodeDB{}) {
		return nil
	}

	delNode, err := ui.AskYesNo("Delete node?")
	if err != nil {
		ui.PrintError("Failed to read answer", err)
		return err
	}

	if delNode {
		err = requests.DelNode(dirConn, &selectedNode.ESAMPubKey, opts.NetTimeout)
		if err != nil {
			ui.PrintError("Failed to delete node", err)
			return err
		} else {
			ui.PrintInfo("Node deleted successfully")
		}
	}

	return nil
}

func passKeyPasswordHandler(c *cli.Context) error {
	var (
		err error

		esamKeyPassword string
		clientConn      net.Conn
	)

	clientConn, err = net.DialTimeout("unix", os.ExpandEnv(c.String("uds-path")), opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to connect to authenticated Client", err)
		return err
	}
	defer clientConn.Close()

	esamKeyPassword, err = ui.ReadPassword("Enter a ESAM key password:", nil)
	if err != nil {
		ui.PrintError("Failed to read password", err)
		return err
	}

	err = requests.PassKeyPassword(clientConn, esamKeyPassword, opts.NetTimeout)
	if err != nil {
		ui.PrintError("Failed to pass key password", err)
		return err
	} else {
		ui.PrintInfo("Key password passed successfully")
	}

	return nil
}

func makeDirConnSettings(esamKeyPath string, dirAddr string, dirPort string, tlsCACertPath string, verifyKeyPath string) (*data.DirConnSettings, error) {
	var (
		err             error
		dirConnSettings *data.DirConnSettings
	)

	dirConnSettings = new(data.DirConnSettings)

	dirConnSettings.ESAMKeyPath, err = filepath.Abs(esamKeyPath)
	if err != nil {
		return nil, err
	}

	dirConnSettings.DirAddr = dirAddr
	dirConnSettings.DirPort = dirPort

	dirConnSettings.TLSCaCertPath, err = filepath.Abs(tlsCACertPath)
	if err != nil {
		return nil, err
	}

	dirConnSettings.VerifyKeyPath, err = filepath.Abs(verifyKeyPath)
	if err != nil {
		return nil, err
	}

	return dirConnSettings, nil
}

func connectToDirectorOnOneTry(udsPath string, dirUDSPath string) (net.Conn, *login.Context, error) {
	var (
		err                error
		dirConn            net.Conn
		loginContext       *login.Context
		esamKeyIsEncrypted bool
		esamKeyPassword    string
	)

	if os.ExpandEnv(dirUDSPath) != "" {
		dirConn, err = net.DialTimeout("unix", os.ExpandEnv(dirUDSPath), opts.NetTimeout)
		if err != nil {
			return nil, nil, err
		}
	} else {
		var (
			dirConnSettings data.DirConnSettings
		)

		getDirConnSettings := func() error {
			var (
				err        error
				clientConn net.Conn
			)

			clientConn, err = net.DialTimeout("unix", os.ExpandEnv(udsPath), opts.NetTimeout)
			if err != nil {
				return err
			}
			defer clientConn.Close()

			err = requests.GetDirConnSettings(clientConn, &dirConnSettings, opts.NetTimeout)
			if err != nil {
				return err
			}

			return nil
		}

		err = getDirConnSettings()
		if err != nil {
			return nil, nil, err
		}

		esamKeyIsEncrypted, err = keysconv.KeyIsEncrypted(dirConnSettings.ESAMKeyPath)
		if err != nil {
			return nil, nil, err
		}

		if esamKeyIsEncrypted {
			esamKeyPassword, err = ui.ReadPassword("Enter a ESAM key password:", nil)
			if err != nil {
				return nil, nil, err
			}
		}

		loginContext, err = login.MakeContext(dirConnSettings.ESAMKeyPath, dirConnSettings.DirAddr, dirConnSettings.DirPort, dirConnSettings.TLSCaCertPath, dirConnSettings.VerifyKeyPath, esamKeyPassword)
		if err != nil {
			return nil, nil, err
		}

		dirConn, err = tls.DialWithDialer(&net.Dialer{Timeout: opts.NetTimeout}, "tcp", dirConnSettings.DirAddr+":"+dirConnSettings.DirPort, &loginContext.TLSConfig)
		if err != nil {
			return nil, nil, err
		}

		err = requests.Auth(dirConn, &loginContext.ESAMPubKey, loginContext.Key, true, opts.NetTimeout)
		if err != nil {
			return nil, nil, err
		}
	}

	return dirConn, loginContext, nil
}

func filterNodeAuthList(nodesListIn []data.NodeAuth, nodeFilter *data.NodeAuth, fullMatch bool) ([]data.NodeAuth, error) {
	var (
		nodesList    []data.NodeAuth
		nodesListTmp []data.NodeAuth
	)

	nodesList = nodesListIn

	if nodeFilter.Name != "" {
		nodesListTmp = make([]data.NodeAuth, 0)
		for index := range nodesList {
			if fullMatch {
				if nodesList[index].Name == nodeFilter.Name {
					nodesListTmp = append(nodesListTmp, nodesList[index])
				}
			} else {
				if strings.Contains(nodesList[index].Name, nodeFilter.Name) {
					nodesListTmp = append(nodesListTmp, nodesList[index])
				}
			}
		}
		nodesList = nodesListTmp
	}

	if nodeFilter.TrustedData != "" {
		nodesListTmp = make([]data.NodeAuth, 0)
		for index := range nodesList {
			if nodesList[index].TrustedData == nodeFilter.TrustedData {
				nodesListTmp = append(nodesListTmp, nodesList[index])
			}
		}
		nodesList = nodesListTmp
	}

	return nodesList, nil
}
