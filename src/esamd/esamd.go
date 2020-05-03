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
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

import (
	"esam/src/auth"
	"esam/src/crypt"
	"esam/src/data"
	"esam/src/db"
	"esam/src/keysconv"
	"esam/src/misc"
	"esam/src/netapi"
	"esam/src/netmsg"
	"esam/src/opts"
	"esam/src/opts2"
	"esam/src/passwd"
	"esam/src/ui"
)

import (
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

const (
	AppDescription = "ESAM (Elementary SSH accounts management) Director"
	AppVersion     = "0.2"
)

const (
	SessionEventUnknown = iota
	SessionEventStarted
	SessionEventEnded
)

type sessionEventType struct {
	Event       int
	sessionData *sessionDataType
}

const (
	DataEventUnknown = iota
	DataEventAddUser
	DataEventUpdateUser
	DataEventChangePassword
	DataEventDelUser
	DataEventAddNode
	DataEventUpdateNode
	DataEventDelNode
)

const (
	DataNoticeUnknown = iota
	DataNoticeUpdatedUsers
	DataNoticeUpdatedNodes
)

type dataEventType struct {
	Event   int
	OldData interface{}
	NewData interface{}
}

type globDataType struct {
	DB              db.Desc
	SessionsEvents  chan sessionEventType
	DataEvents      chan dataEventType
	AccessReqSecret string
}

type sessionDataType struct {
	AuthContext                *auth.Context
	Conn                       net.Conn
	Context                    context.Context
	Terminate                  context.CancelFunc
	NoticesNotRequiredByClient bool
	DataChangeNotice           chan int
	PubKey                     *rsa.PublicKey

	onceConnClose sync.Once
}

func (session *sessionDataType) CloseConn() {
	closeConn := func() {
		session.Conn.Close()
	}

	if session.Conn != nil {
		session.onceConnClose.Do(closeConn)
	}
}

func main() {
	var err error
	var app *cli.App

	log.SetFormatter(&log.JSONFormatter{})

	syscall.Umask(0077)
	syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)

	app = cli.NewApp()
	app.Usage = AppDescription
	app.Version = AppVersion
	app.EnableBashCompletion = true

	startFlags := []cli.Flag{
		&cli.StringFlag{
			Name:  "config",
			Value: "",
			Usage: "path to the configuration file",
		},
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "db-name",
				Value: "esamd",
				Usage: "name of the database used",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-type",
				Value: "sqlite",
				Usage: "type of DBMS",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-addr",
				Value: "esamd.db",
				Usage: "address of connection to DBMS or database file path",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-port",
				Value: "",
				Usage: "port of connection to DBMS",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-user",
				Value: "",
				Usage: "DBMS user",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-password",
				Value: "",
				Usage: "DBMS user password",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "listen-addr",
				Value: "127.0.0.1",
				Usage: "listening address",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "listen-port",
				Value: "",
				Usage: "listening port",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "tls-key",
				Value: "",
				Usage: "path to the private key file used for TLS",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "tls-cert",
				Value: "",
				Usage: "path to the certificate file used for TLS",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "access-req-secret",
				Value: "",
				Usage: "random sequence used for simple authentication when sending an access request",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "uds-path",
				Value: "esamd.socket",
				Usage: "path to the Unix socket used for local management of the Director",
			}),
	}

	initDBFlags := []cli.Flag{
		&cli.StringFlag{
			Name:  "config",
			Value: "",
			Usage: "path to the configuration file",
		},
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "db-name",
				Value: "esamd",
				Usage: "name of the created database",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-type",
				Value: "sqlite",
				Usage: "type of DBMS",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-addr",
				Value: "esamd.db",
				Usage: "address of connection to DBMS or database file path",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-port",
				Value: "",
				Usage: "port of connection to DBMS",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-user",
				Value: "",
				Usage: "DBMS user",
			}),
		altsrc.NewStringFlag(
			&cli.StringFlag{
				Name:  "dbms-password",
				Value: "",
				Usage: "DBMS user password",
			}),
	}

	app.Commands = []*cli.Command{
		{
			Name:         "init-db",
			Usage:        "Create a Director's database and tables in it",
			Action:       initDBHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Before:       altsrc.InitInputSourceWithContext(initDBFlags, altsrc.NewYamlSourceFromFlagFunc("config")),
			Flags:        initDBFlags,
		},
		{
			Name:         "start",
			Usage:        "Run in main operation mode",
			Action:       startHandler,
			BashComplete: misc.SubCommandBashCompleter,
			Before:       altsrc.InitInputSourceWithContext(startFlags, altsrc.NewYamlSourceFromFlagFunc("config")),
			Flags:        startFlags,
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		os.Exit(1)
	}
}

func initDBHandler(c *cli.Context) error {
	var err error
	var db db.Desc

	err = db.Connect(c.String("dbms-type"), c.String("dbms-addr"), c.String("dbms-port"), c.String("dbms-user"), c.String("dbms-password"), c.String("db-name"))
	if err != nil {
		ui.PrintError("Failed to open database", err)
		return err
	}

	err = db.Init()
	if err != nil {
		ui.PrintError("Failed to init database", err)
		return err
	}

	err = db.Test()
	if err != nil {
		ui.PrintError("Failed to test database", err)
		return err
	}

	ui.PrintInfo("DB initialization completed successfully")

	return nil
}

func startHandler(c *cli.Context) error {
	var err error
	var globData globDataType

	var tlsConfig tls.Config
	var tlsKeyPair tls.Certificate
	var tlsListener net.Listener
	var udsListener net.Listener
	var waitSessions sync.WaitGroup
	var waitSessionsManager sync.WaitGroup

	sessionsCtx, sessionsCancel := context.WithCancel(context.Background())
	sessionsManagerCtx, sessionsManagerCancel := context.WithCancel(context.Background())

	log.Println("Start logging")

	err = globData.DB.Connect(c.String("dbms-type"), c.String("dbms-addr"), c.String("dbms-port"), c.String("dbms-user"), c.String("dbms-password"), c.String("db-name"))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to open database")
		return err
	}

	err = globData.DB.Test()
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to test database")
		return err
	}

	globData.SessionsEvents = make(chan sessionEventType, 0)
	globData.DataEvents = make(chan dataEventType, opts.DataEventChanCapacity)
	globData.AccessReqSecret = c.String("access-req-secret")

	tlsKeyPair, err = tls.LoadX509KeyPair(c.String("tls-cert"), c.String("tls-key"))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to load TLS cert or key")
		return err
	}

	tlsConfig.MinVersion = opts.TLSMinVersion
	tlsConfig.Certificates = []tls.Certificate{tlsKeyPair}

	tlsListener, err = tls.Listen("tcp", c.String("listen-addr")+":"+c.String("listen-port"), &tlsConfig)
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to allocate TLS network listener")
		return err
	}

	udsListener, err = net.Listen("unix", c.String("uds-path"))
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to allocate UDS network listener")
		return err
	}

	waitSessions.Add(2)
	waitSessionsManager.Add(1)

	go sessionsManager(sessionsManagerCtx, &globData, &waitSessionsManager)
	go tlsLoop(sessionsCtx, tlsListener, &globData, &waitSessions)
	go udsLoop(sessionsCtx, udsListener, &globData, &waitSessions)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	signalReceiver := <-signalChan
	log.Printf("Received signal '%v' - terminating", signalReceiver)

	sessionsCancel()

	tlsListener.Close()
	udsListener.Close()

	waitSessions.Wait()

	sessionsManagerCancel()

	waitSessionsManager.Wait()

	log.Println("Stop logging")

	return nil
}

func sessionsManager(ctx context.Context, globData *globDataType, wait *sync.WaitGroup) {
	defer wait.Done()

	var sessionEvent sessionEventType
	var dataEvent dataEventType

	var sessionDataMap map[(*sessionDataType)](*sessionDataType)
	var dataEventMap map[time.Time]dataEventType

	var sessionCloserTimer <-chan time.Time

	sessionDataMap = make(map[(*sessionDataType)](*sessionDataType))
	dataEventMap = make(map[time.Time]dataEventType)

	sessionCloserTimer = time.After(opts.SessionCloserPeriod)

	for {
		select {
		case <-ctx.Done():
			{
				return
			}

		case sessionEvent = <-globData.SessionsEvents:
			{
				switch sessionEvent.Event {
				case SessionEventStarted:
					{
						sessionDataMap[sessionEvent.sessionData] = sessionEvent.sessionData
					}

				case SessionEventEnded:
					{
						delete(sessionDataMap, sessionEvent.sessionData)
					}

				default:
					{
						log.Errorln("Unsupported session event received")
					}
				}
			}

		case dataEvent = <-globData.DataEvents:
			{
				var dataNotice int

				dataEventMap[time.Now()] = dataEvent
				dataNotice = DataNoticeUnknown

				switch dataEvent.Event {
				case DataEventAddUser, DataEventUpdateUser, DataEventChangePassword, DataEventDelUser:
					{
						dataNotice = DataNoticeUpdatedUsers
					}

				case DataEventAddNode, DataEventUpdateNode, DataEventDelNode:
					{
						dataNotice = DataNoticeUpdatedNodes
					}
				}

				if dataNotice != DataNoticeUnknown {
					for _, sessionData := range sessionDataMap {
						/* For send data change notices to sessions used non-blocking io to prevent deadlocks */
						select {
						case sessionData.DataChangeNotice <- dataNotice:
						default:
							{
								log.Errorln("Failed to send data change notice")
							}
						}
					}
				}
			}

		case <-sessionCloserTimer:
			{
				sessionCloserTimer = time.After(opts.SessionCloserPeriod)

				for dataEventTime, dataEventValue := range dataEventMap {
					if time.Since(dataEventTime) >= opts.DataEventLifeTime {
						delete(dataEventMap, dataEventTime)
					}

					for _, sessionData := range sessionDataMap {
						var userEventOldData data.User
						var userEventNewData data.User
						var userSubjectData data.User
						var nodeEventOldData data.Node
						var nodeSubjectData data.Node

						var castEventOldDataOk bool
						var castEventNewDataOk bool
						var castSubjectDataOk bool

						if sessionData.AuthContext == nil {
							log.Errorln("Session auth context turned out to be nil")
							continue
						}

						switch dataEventValue.Event {
						case DataEventUpdateUser:
							{
								userEventOldData, castEventOldDataOk = dataEventValue.OldData.(data.User)
								userEventNewData, castEventNewDataOk = dataEventValue.NewData.(data.User)
								userSubjectData, castSubjectDataOk = sessionData.AuthContext.SubjectData.(data.User)

								if castEventOldDataOk && castEventNewDataOk && castSubjectDataOk {
									if userSubjectData.ESAMPubKey.Equal(&userEventOldData.ESAMPubKey) {
										sessionData.Terminate()
										if userEventNewData.State != data.UserStateEnabled {
											/* Increases reliable, but requires access synchronization
											   sessionData.AuthContext.SubjectType = auth.SubjectUnknown
											*/
											sessionData.CloseConn()
										} else {
											delete(dataEventMap, dataEventTime)
										}
									}
								}
							}

						case DataEventDelUser:
							{
								userEventOldData, castEventOldDataOk = dataEventValue.OldData.(data.User)
								userSubjectData, castSubjectDataOk = sessionData.AuthContext.SubjectData.(data.User)

								if castEventOldDataOk && castSubjectDataOk {
									if userSubjectData.ESAMPubKey.Equal(&userEventOldData.ESAMPubKey) {
										sessionData.Terminate()
										sessionData.CloseConn()
									}
								}
							}

						case DataEventUpdateNode:
							{
								nodeEventOldData, castEventOldDataOk = dataEventValue.OldData.(data.Node)
								nodeSubjectData, castSubjectDataOk = sessionData.AuthContext.SubjectData.(data.Node)

								if castEventOldDataOk && castSubjectDataOk {
									if nodeSubjectData.ESAMPubKey.Equal(&nodeEventOldData.ESAMPubKey) {
										sessionData.Terminate()
										delete(dataEventMap, dataEventTime)
									}
								}
							}

						case DataEventDelNode:
							{
								nodeEventOldData, castEventOldDataOk = dataEventValue.OldData.(data.Node)
								nodeSubjectData, castSubjectDataOk = sessionData.AuthContext.SubjectData.(data.Node)

								if castEventOldDataOk && castSubjectDataOk {
									if nodeSubjectData.ESAMPubKey.Equal(&nodeEventOldData.ESAMPubKey) {
										sessionData.Terminate()
										sessionData.CloseConn()
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func tlsLoop(ctx context.Context, listener net.Listener, globData *globDataType, wait *sync.WaitGroup) {
	defer wait.Done()

	var err error
	var tlsConn net.Conn
	var waitConn sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			{
				waitConn.Wait()
				return
			}

		default:
			{
				tlsConn, err = listener.Accept()
				if err != nil {
					if netmsg.IsTemporary(err) {
						log.WithFields(log.Fields{"details": err}).Errorln("Failed to accept TLS connection")
					}
				} else {
					waitConn.Add(1)
					go tlsConnHandler(ctx, tlsConn, globData, &waitConn)
				}
			}
		}
	}

	return
}

func udsLoop(ctx context.Context, listener net.Listener, globData *globDataType, wait *sync.WaitGroup) {
	defer wait.Done()

	var err error
	var udsConn net.Conn
	var waitConn sync.WaitGroup

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
					go udsConnHandler(ctx, udsConn, globData, &waitConn)
				}
			}
		}
	}

	return
}

func tlsConnHandler(ctx context.Context, conn net.Conn, globData *globDataType, wait *sync.WaitGroup) {
	defer wait.Done()

	var err error
	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader

	var requireSendErrorReply bool
	var reasonSendErrorReply string
	var connStartTime time.Time

	requireSendErrorReply = true
	reasonSendErrorReply = netapi.ReqResultReasonEmpty
	connStartTime = time.Now()

	var deferCloseConnNotRequired bool

	closeConn := func() {
		if !deferCloseConnNotRequired {
			conn.Close()
		}
	}

	defer closeConn()

	sendErrorReply := func() {
		var err error

		if requireSendErrorReply {
			time.Sleep(opts.DelayBeforeSendErrorReplyInUnAuthConn - time.Since(connStartTime))

			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusFailed, reasonSendErrorReply})
			if err == nil {
				_, _ = netmsg.Send(conn, msgOut[:], opts.NetTimeout)
			}
		}
	}

	sendSuccessfulReply := func() {
		var err error

		if !requireSendErrorReply {
			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusSuccessful, netapi.ReqResultReasonEmpty})
			if err == nil {
				_, _ = netmsg.Send(conn, msgOut[:], opts.NetTimeout)
			}
		}
	}

	msgIn, err = netmsg.Recv(conn, opts.NetTimeout)
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to receive message")
		return
	}

	err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
	if err != nil {
		log.WithFields(log.Fields{"details": err}).Errorln("Failed to parse message header")
		return
	}

	switch msgInHeader.Type {
	case netapi.MsgTypeRequest:
		{
			switch msgInHeader.SubType {
			case netapi.ReqTypeAddAccessReq:
				{
					processAccessReq := func() error {
						defer sendErrorReply()
						defer sendSuccessfulReply()

						var err error
						var accessReq data.AccessReq
						var accessReqSecret string
						var accessReqListLen uint
						var accessReqDB data.AccessReqDB

						err = netapi.ParseReqAddAccessReq(msgIn[:], &accessReq, &accessReqSecret)
						if err != nil {
							return err
						}

						if subtle.ConstantTimeCompare([]byte(accessReqSecret), []byte(globData.AccessReqSecret)) != 1 {
							return errors.New("Access request unauthenticated")
						}

						err = accessReq.Normalize(data.ToleratesEmptyFieldsNo)
						if err != nil {
							return err
						}

						err = accessReq.Test(data.ToleratesEmptyFieldsNo)
						if err != nil {
							return err
						}

						accessReqListLen, err = globData.DB.GetAccessReqCount()
						if err != nil {
							return err
						}

						if accessReqListLen >= opts.AccessReqListLimit {
							return errors.New("Access request limit reached")
						}

						accessReqDB.AccessReq = accessReq
						accessReqDB.Addr = misc.ExtractAddr(conn.RemoteAddr().String())
						accessReqDB.Time = time.Now()

						err = globData.DB.AddAccessReq(&accessReqDB)
						if err != nil {
							return err
						}

						requireSendErrorReply = false

						return nil
					}

					err = processAccessReq()
					if err != nil {
						log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
					}

					return
				}

			case netapi.ReqTypeAuth:
				{
					processAuth := func() (*sessionDataType, error) {
						defer sendErrorReply()
						defer sendSuccessfulReply()

						var err error
						var sessionData *sessionDataType
						var subjectESAMPubKey data.ESAMPubKey

						var maxCryptTextSize uint
						var authQuestion []byte
						var authQuestionEncrypted []byte
						var authAnswer []byte

						sessionData = new(sessionDataType)

						sessionData.NoticesNotRequiredByClient, err = netapi.ParseReqAuthStageOne(msgIn[:], &subjectESAMPubKey)
						if err != nil {
							return nil, err
						}

						err = subjectESAMPubKey.Normalize(data.ToleratesEmptyFieldsNo)
						if err != nil {
							return nil, err
						}

						err = subjectESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
						if err != nil {
							return nil, err
						}

						/*
						   - определение Subject по предоставленному ключу
						   - генерирование authQuestion
						   - отправка ответного сообщения с вопросом
						   - проверка ответа
						*/

						sessionData.AuthContext, err = auth.IdentifySubject(&subjectESAMPubKey, &(globData.DB))
						if err != nil {
							return nil, err
						}

						sessionData.PubKey, err = keysconv.PubKeyInPEMToRSA(subjectESAMPubKey[:])
						if err != nil {
							return nil, err
						}

						maxCryptTextSize, err = crypt.GetMaxTextSizeByKey(sessionData.PubKey)
						if err != nil {
							return nil, err
						}

						if maxCryptTextSize < opts.MinAuthQuestionSize {
							return nil, errors.New("Maximum size of the encrypted text for the specified key is less than the minimum")
						}

						authQuestion, err = crypt.RandBytes(opts.MinAuthQuestionSize)
						if err != nil {
							return nil, err
						}

						authQuestionEncrypted, err = crypt.Encrypt(authQuestion[:], sessionData.PubKey)
						if err != nil {
							return nil, err
						}

						msgOut, err = netapi.BuildRepAuthStageOne(authQuestionEncrypted)
						if err != nil {
							return nil, err
						}

						_, err = netmsg.Send(conn, msgOut[:], opts.NetTimeout)
						if err != nil {
							return nil, err
						}

						msgIn, err = netmsg.Recv(conn, opts.NetTimeout)
						if err != nil {
							return nil, err
						}

						authAnswer, err = netapi.ParseReqAuthStageTwo(msgIn[:])
						if err != nil {
							return nil, err
						}

						if subtle.ConstantTimeCompare(authAnswer[:], authQuestion[:]) == 1 {
							requireSendErrorReply = false

							return sessionData, nil
						}

						return nil, errors.New("Unknown error")
					}

					var sessionData *sessionDataType = nil

					sessionData, err = processAuth()
					if err != nil {
						log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
						return
					}

					if sessionData == nil {
						log.Errorln("Session data was not defined at auth process")
						return
					}

					if sessionData.AuthContext == nil {
						log.Errorln("Auth context was not defined at auth process")
						return
					}

					deferCloseConnNotRequired = true

					sessionData.Conn = conn
					sessionData.Context, sessionData.Terminate = context.WithCancel(ctx)
					sessionData.DataChangeNotice = make(chan int, opts.DataEventChanCapacity)

					globData.SessionsEvents <- sessionEventType{Event: SessionEventStarted, sessionData: sessionData}

					generalLoop(globData, sessionData)

					globData.SessionsEvents <- sessionEventType{Event: SessionEventEnded, sessionData: sessionData}

					close(sessionData.DataChangeNotice)
					sessionData.CloseConn()

					//log.Println("Session is over")

					return
				}

			default:
				{
					log.Errorln("Unsupported at this stage request was received")
					return
				}
			}
		}

	case netapi.MsgTypeReply:
		{
			log.Errorln("Message type 'reply' is not expected at this stage")
			return
		}

	case netapi.MsgTypeNotice:
		{
			log.Errorln("Message type 'notice' is not expected at this stage")
			return
		}

	default:
		{
			log.Errorln("Unsupported message was received")
			return
		}
	}

	log.Errorln("Unknown error at the beginning of the connection process")

	return
}

func udsConnHandler(ctx context.Context, conn net.Conn, globData *globDataType, wait *sync.WaitGroup) {
	defer wait.Done()

	var udsSessionData *sessionDataType = nil

	udsSessionData = &sessionDataType{
		AuthContext: &auth.Context{
			SubjectType: auth.SubjectUDS,
			SubjectData: nil,
		},
		NoticesNotRequiredByClient: true,
		PubKey:                     nil,
	}

	udsSessionData.Conn = conn
	udsSessionData.Context, udsSessionData.Terminate = context.WithCancel(ctx)
	udsSessionData.DataChangeNotice = make(chan int, opts.DataEventChanCapacity)

	globData.SessionsEvents <- sessionEventType{Event: SessionEventStarted, sessionData: udsSessionData}

	generalLoop(globData, udsSessionData)

	globData.SessionsEvents <- sessionEventType{Event: SessionEventEnded, sessionData: udsSessionData}

	close(udsSessionData.DataChangeNotice)
	udsSessionData.CloseConn()

	return
}

func generalLoop(globData *globDataType, sessionData *sessionDataType) {
	var err error

	var msgIn []byte
	var msgOut []byte
	var msgInHeader netapi.MsgHeader

	var noMsgTimer <-chan time.Time
	var noopTimer <-chan time.Time

	var requireSendErrorReply bool
	var reasonSendErrorReply string

	sendErrorReply := func() {
		var err error

		if requireSendErrorReply {
			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusFailed, reasonSendErrorReply})
			if err == nil {
				_, _ = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
			}
		}
	}

	sendSuccessfulReply := func() {
		var err error

		if !requireSendErrorReply {
			msgOut, err = netapi.BuildSimpleRep(msgInHeader.SubType, &netapi.ReqResult{netapi.ReqResultStatusSuccessful, netapi.ReqResultReasonEmpty})
			if err == nil {
				_, _ = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
			}
		}
	}

	sendNoop := func(netTimeout time.Duration) error {
		var err error

		msgOut, err = netapi.BuildNotice(netapi.NoticeTypeNoop)
		if err != nil {
			return err
		}

		_, err = netmsg.Send(sessionData.Conn, msgOut[:], netTimeout)
		if err != nil {
			return err
		}

		return nil
	}

	sendNotice := func(notice string, netTimeout time.Duration) error {
		var err error

		msgOut, err = netapi.BuildNotice(notice)
		if err != nil {
			return err
		}

		_, err = netmsg.Send(sessionData.Conn, msgOut[:], netTimeout)
		if err != nil {
			return err
		}

		return nil
	}

	sendDataEvent := func(dataEvent dataEventType) {
		/* For send event to sessions manager used blocking io to guaranteed notification of the need to reopen or close related sessions */
		globData.DataEvents <- dataEvent
	}

	noMsgTimer = time.After(opts.NoMsgThresholdTime)
	noopTimer = time.After(opts.NoopNoticePeriod)

	for {
		select {
		case <-sessionData.Context.Done():
			{
				return
			}

		case <-noMsgTimer:
			{
				if !sessionData.NoticesNotRequiredByClient {
					log.WithFields(log.Fields{"details": err}).Errorln("Messages were missing more than the threshold time - close connection")
					return
				}
			}

		case <-noopTimer:
			{
				noopTimer = time.After(opts.NoopNoticePeriod)

				if !sessionData.NoticesNotRequiredByClient {
					err = sendNoop(opts.NetTimeout)
					if err != nil {
						log.WithFields(log.Fields{"details": err}).Errorln("Failed to send noop notice")
						return
					}
				}
			}

		case dataChangeNotice, chanReady := <-sessionData.DataChangeNotice:
			{
				if !sessionData.NoticesNotRequiredByClient && chanReady {
					switch dataChangeNotice {
					case DataNoticeUpdatedUsers:
						{
							err = sendNotice(netapi.NoticeTypeUpdatedUsers, opts.NetTimeout)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to send notice")
								return
							}
						}

					case DataNoticeUpdatedNodes:
						{
							err = sendNotice(netapi.NoticeTypeUpdatedNodes, opts.NetTimeout)
							if err != nil {
								log.WithFields(log.Fields{"details": err}).Errorln("Failed to send notice")
								return
							}
						}

					default:
						{
							log.Errorln("Unsupported data event received")
						}
					}
				}
			}

		default:
			{
				requireSendErrorReply = true
				reasonSendErrorReply = netapi.ReqResultReasonInternalError

				msgIn, err = netmsg.Recv(sessionData.Conn, opts.NetTimeout)
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

				err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
				if err != nil {
					log.WithFields(log.Fields{"details": err}).Errorln("Failed to parse message header")
					continue
				}

				switch msgInHeader.Type {
				case netapi.MsgTypeRequest:
					{
						noMsgTimer = time.After(opts.NoMsgThresholdTime)

						switch msgInHeader.SubType {
						case netapi.ReqTypeListAccessReqs:
							{
								processListAccessReqs := func() error {
									defer sendErrorReply()

									var err error
									var accessGranted bool

									var filter data.AccessReqDB
									var list []data.AccessReqDB

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									err = netapi.ParseReqListAccessReqs(msgIn[:], &filter)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = filter.Normalize(data.ToleratesEmptyFieldsYes)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = filter.Test(data.ToleratesEmptyFieldsYes)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									list, err = globData.DB.ListAccessReqs(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("Access request not found")
									}

									requireSendErrorReply = false

									msgOut, err = netapi.BuildRepListAccessReqs(list[:])
									if err != nil {
										return err
									}

									_, err = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
									if err != nil {
										return err
									}

									return nil
								}

								err = processListAccessReqs()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeDelAccessReq:
							{
								processDelAccessReq := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var targetESAMPubKey data.ESAMPubKey
									var filter data.AccessReqDB
									var list []data.AccessReqDB

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									err = netapi.ParseReqDelAccessReq(msgIn[:], &targetESAMPubKey)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Normalize(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД на наличие такого запроса
									filter.ESAMPubKey = targetESAMPubKey
									list, err = globData.DB.ListAccessReqs(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("Access request not found")
									}

									if len(list[:]) > 1 {
										return errors.New("Provided ESAM pub key found in multiplicity access requests - integrity violation")
									}

									// Если такой запрос присутствует - удаление этого запроса
									err = globData.DB.DelAccessReq(targetESAMPubKey)
									if err != nil {
										return err
									}

									requireSendErrorReply = false

									return nil
								}

								err = processDelAccessReq()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeAddUser:
							{
								processAddUser := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var newUser data.UserDB
									var filter data.User
									var list []data.UserDB

									err = netapi.ParseReqAddUser(msgIn[:], &newUser)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newUser.Normalize()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newUser.Test()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, newUser, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Запрос к БД на наличие такого пользователя
									filter.ESAMPubKey = newUser.ESAMPubKey
									list, err = globData.DB.ListUsers(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) > 0 {
										reasonSendErrorReply = netapi.ReqResultReasonAlreadyExist
										return errors.New("User already exist")
									}

									// Если такого пользователя нет - добавление пользователя в БД
									err = globData.DB.AddUser(&newUser)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventAddUser, NewData: newUser.User})

									requireSendErrorReply = false

									globData.DB.DelAccessReq(newUser.ESAMPubKey)

									return nil
								}

								err = processAddUser()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeUpdateUser:
							{
								processUpdateUser := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var targetESAMPubKey data.ESAMPubKey
									var newUser data.UserDB
									var filter data.User
									var list []data.UserDB

									err = netapi.ParseReqUpdateUser(msgIn[:], &targetESAMPubKey, &newUser)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Normalize(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newUser.Normalize()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newUser.Test()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД на наличие такого пользователя
									filter.ESAMPubKey = targetESAMPubKey
									list, err = globData.DB.ListUsers(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("User not found")
									}

									if len(list[:]) > 1 {
										return errors.New("Provided ESAM pub key found in multiplicity users - integrity violation")
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, newUser, list[0], msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Если такой пользователь присутствует - обновление данных пользователя в БД
									err = globData.DB.UpdateUser(&filter, &newUser)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventUpdateUser, OldData: list[0].User, NewData: newUser.User})

									requireSendErrorReply = false

									return nil
								}

								err = processUpdateUser()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeChangePassword:
							{
								processChangePassword := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var castOk bool
									var accessGranted bool

									var password string
									var passwordHash string
									var passwordHashSign []byte
									var sessionUserData data.User
									var filter data.User
									var list []data.UserDB
									var newUserData *data.UserDB

									password, passwordHash, passwordHashSign, err = netapi.ParseReqChangePassword(msgIn[:])
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									if passwd.CompareHash(password, passwordHash, opts2.PasswdHashAlgo) == false {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = passwd.CheckDifficulty(password, &opts2.PasswdDifficulty)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonPasswordTooSimple
										return err
									}

									sessionUserData, castOk = sessionData.AuthContext.SubjectData.(data.User)
									if !castOk {
										return errors.New("Failed to cast subject data to user data")
									}

									// Запрос к БД на наличие такого пользователя
									filter.ESAMPubKey = sessionUserData.ESAMPubKey
									list, err = globData.DB.ListUsers(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("User not found")
									}

									if len(list[:]) > 1 {
										return errors.New("Provided ESAM pub key found in multiplicity users - integrity violation")
									}

									newUserData, err = list[0].Copy()
									if err != nil {
										return err
									}

									newUserData.User.PasswordHash = passwordHash
									newUserData.UserSign.PasswordHashSign = passwordHashSign[:]

									err = newUserData.Normalize()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newUserData.Test()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newUserData.Verify(map[string]bool{"PasswordHash": true})
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, (*newUserData), list[0], msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Если такой пользователь присутствует - обновление данных пользователя в БД
									err = globData.DB.UpdateUser(&filter, newUserData)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventChangePassword, OldData: list[0].User})

									requireSendErrorReply = false

									return nil
								}

								err = processChangePassword()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeListUsers:
							{
								processListUsers := func() error {
									defer sendErrorReply()

									var err error
									var accessGranted bool

									var filter data.User
									var list []data.UserDB

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									err = netapi.ParseReqListUsers(msgIn[:], &filter)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = filter.Normalize(data.ToleratesEmptyFieldsYes)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = filter.Test(data.ToleratesEmptyFieldsYes)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД
									list, err = globData.DB.ListUsers(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("User not found")
									}

									requireSendErrorReply = false

									msgOut, err = netapi.BuildRepListUsers(list[:])
									if err != nil {
										return err
									}

									_, err = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
									if err != nil {
										return err
									}

									return nil
								}

								err = processListUsers()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeDelUser:
							{
								processDelUser := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var targetESAMPubKey data.ESAMPubKey
									var filter data.User
									var list []data.UserDB

									err = netapi.ParseReqDelUser(msgIn[:], &targetESAMPubKey)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Normalize(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД на наличие такого пользователя
									filter.ESAMPubKey = targetESAMPubKey
									list, err = globData.DB.ListUsers(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("User not found")
									}

									if len(list[:]) > 1 {
										return errors.New("Provided ESAM pub key found in multiplicity user - integrity violation")
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, list[0], msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Если такой пользователь присутствует - удаление этого пользователя
									err = globData.DB.DelUser(targetESAMPubKey)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventDelUser, OldData: list[0].User})

									requireSendErrorReply = false

									return nil
								}

								err = processDelUser()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeAddNode:
							{
								processAddNode := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var newNode data.NodeDB
									var filter data.Node
									var list []data.NodeDB

									err = netapi.ParseReqAddNode(msgIn[:], &newNode)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newNode.Normalize()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newNode.Test()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, newNode, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Запрос к БД на наличие такого управляемого узла
									filter.ESAMPubKey = newNode.ESAMPubKey
									list, err = globData.DB.ListNodes(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) > 0 {
										reasonSendErrorReply = netapi.ReqResultReasonAlreadyExist
										return errors.New("Node already exist")
									}

									// Если такого управляемого узла нет - добавление управляемого узла в БД
									err = globData.DB.AddNode(&newNode)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventAddNode, NewData: newNode.Node})

									requireSendErrorReply = false

									globData.DB.DelAccessReq(newNode.ESAMPubKey)

									return nil
								}

								err = processAddNode()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeUpdateNode:
							{
								processUpdateNode := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var targetESAMPubKey data.ESAMPubKey
									var newNode data.NodeDB
									var filter data.Node
									var list []data.NodeDB

									err = netapi.ParseReqUpdateNode(msgIn[:], &targetESAMPubKey, &newNode)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Normalize(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newNode.Normalize()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = newNode.Test()
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД на наличие такого управляемого узла
									filter.ESAMPubKey = targetESAMPubKey
									list, err = globData.DB.ListNodes(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("Node not found")
									}

									if len(list[:]) > 1 {
										return errors.New("Provided ESAM pub key found in multiplicity nodes - integrity violation")
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Если такой управляемый узел присутствует - обновление данных управляемого узла в БД
									err = globData.DB.UpdateNode(&filter, &newNode)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventUpdateNode, OldData: list[0].Node, NewData: newNode.Node})

									requireSendErrorReply = false

									return nil
								}

								err = processUpdateNode()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeListNodes:
							{
								processListNodes := func() error {
									defer sendErrorReply()

									var err error
									var accessGranted bool

									var filter data.Node
									var list []data.NodeDB

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, nil, msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									err = netapi.ParseReqListNodes(msgIn[:], &filter)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = filter.Normalize(data.ToleratesEmptyFieldsYes)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = filter.Test(data.ToleratesEmptyFieldsYes)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД
									list, err = globData.DB.ListNodes(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("Node not found")
									}

									requireSendErrorReply = false

									msgOut, err = netapi.BuildRepListNodes(list[:])
									if err != nil {
										return err
									}

									_, err = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
									if err != nil {
										return err
									}

									return nil
								}

								err = processListNodes()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
							}

						case netapi.ReqTypeDelNode:
							{
								processDelNode := func() error {
									defer sendErrorReply()
									defer sendSuccessfulReply()

									var err error
									var accessGranted bool

									var targetESAMPubKey data.ESAMPubKey
									var filter data.Node
									var list []data.NodeDB

									err = netapi.ParseReqDelNode(msgIn[:], &targetESAMPubKey)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Normalize(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									err = targetESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
									if err != nil {
										reasonSendErrorReply = netapi.ReqResultReasonInvalidInputData
										return err
									}

									// Запрос к БД на наличие такого управляемого узла
									filter.ESAMPubKey = targetESAMPubKey
									list, err = globData.DB.ListNodes(&filter)
									if err != nil {
										return err
									}

									if len(list[:]) == 0 {
										reasonSendErrorReply = netapi.ReqResultReasonNotFound
										return errors.New("Node not found")
									}

									if len(list[:]) > 1 {
										return errors.New("Provided ESAM pub key found in multiplicity node - integrity violation")
									}

									accessGranted, err = auth.CheckSubjectAccessRights(sessionData.AuthContext, nil, list[0], msgInHeader.SubType)
									if err != nil {
										return err
									}

									if accessGranted == false {
										reasonSendErrorReply = netapi.ReqResultReasonAccessDenied
										return errors.New(netapi.ReqResultReasonAccessDenied)
									}

									// Если такой управляемый узел присутствует - удаление этого управляемого узла
									err = globData.DB.DelNode(targetESAMPubKey)
									if err != nil {
										return err
									}

									sendDataEvent(dataEventType{Event: DataEventDelNode, OldData: list[0].Node})

									requireSendErrorReply = false

									return nil
								}

								err = processDelNode()
								if err != nil {
									log.WithFields(log.Fields{"details": err}).Errorln("Request " + msgInHeader.SubType + " processing error")
									continue
								}
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
							_, _ = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
						}

						continue
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
						default:
							{
								log.Errorln("Unsupported at this stage notice was received")

								msgOut, err = netapi.BuildUnsupportedMsg()
								if err == nil {
									_, _ = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
								}

								continue
							}
						}
					}

				default:
					{
						log.Errorln("Unsupported message was received")

						msgOut, err = netapi.BuildUnsupportedMsg()
						if err == nil {
							_, _ = netmsg.Send(sessionData.Conn, msgOut[:], opts.NetTimeout)
						}

						continue
					}
				}
			}
		}
	}

	return
}
