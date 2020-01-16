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
  "errors"
  "os"
  "os/signal"
  "syscall"
  "sync"
  "crypto/tls"
  "time"
  "context"
  "os/user"
  "fmt"
)

import (
  "esam/src/opts"
  "esam/src/data"
  "esam/src/keysconv"
  "esam/src/ui"
  "esam/src/misc"
  "esam/src/netapi"
  "esam/src/netmsg"
  "esam/src/login"
  "esam/src/requests"
  "esam/src/caches"
  "esam/src/setup"
  "esam/src/types"
  "esam/src/users"
)

import (
  log "github.com/sirupsen/logrus"
  "github.com/urfave/cli/v2"
  "github.com/urfave/cli/v2/altsrc"
  "gopkg.in/yaml.v3"
)

const (
  AppDescription = "ESAM (Elementary SSH accounts management) Agent"
  AppVersion = "0.2"
)

type globDataType struct {
  DataEvents chan bool
  AccessReqSecret string
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
      Name: "config",
      Value: "",
      Usage: "path to the configuration file",
    },
    altsrc.NewStringFlag(
    &cli.StringFlag{
      Name: "esam-key",
      Value: "",
      Usage: "path to the private key file",
    }),
    altsrc.NewStringFlag(
    &cli.StringFlag{
      Name: "dir-addr",
      Value: "",
      Usage: "address of connection to ESAM Director",
    }),
    altsrc.NewStringFlag(
    &cli.StringFlag{
      Name: "dir-port",
      Value: "",
      Usage: "port of connection to ESAM Director",
    }),
    altsrc.NewStringFlag(
    &cli.StringFlag{
      Name: "tls-ca-cert",
      Value: "",
      Usage: "path to the CA certificate file of the signatory of the Director TLS certificate",
    }),
    altsrc.NewStringFlag(
    &cli.StringFlag{
      Name: "verify-key",
      Value: "",
      Usage: "path to the public key file used by the Agent to verify the authenticity of data received from the Director",
    }),
    altsrc.NewStringFlag(
    &cli.StringFlag{
      Name: "access-req-secret",
      Value: "",
      Usage: "random sequence used for simple authentication when sending an access request",
    }),
  }
  
  app.Commands = []*cli.Command{
    {
      Name: "gen-key",
      Usage: "Generate a pair of private and public keys used to authenticate the managed node with the Director",
      Action: genKeyHandler,
      BashComplete: misc.SubCommandBashCompleter,
      Flags: []cli.Flag{
        &cli.StringFlag{
          Name: "esam-key",
          Value: "",
          Usage: "path to the private key file",
        },
        &cli.StringFlag{
          Name: "esam-pub-key",
          Value: "",
          Usage: "path to the public key file",
        },
      },
    },
    {
      Name: "start",
      Usage: "Run in main operation mode",
      Action: startHandler,
      BashComplete: misc.SubCommandBashCompleter,
      Before: altsrc.InitInputSourceWithContext(startFlags, altsrc.NewYamlSourceFromFlagFunc("config")),
      Flags: startFlags,
    },
    {
      Name: "clean",
      Usage: "Delete user accounts created on the current node",
      Action: cleanHandler,
      BashComplete: misc.SubCommandBashCompleter,
    },
  }
  
  err = app.Run(os.Args)
  if err != nil {
    os.Exit(1)
  }
}

func genKeyHandler(c *cli.Context) (error) {
  var err error
  
  err = keysconv.GenAndSaveKeyPair(c.String("esam-key"), c.String("esam-pub-key"), opts.KeySize, "")
  if err != nil {
    ui.PrintError("Failed to generate key pair", err)
    return err
  }
  
  ui.PrintInfo("ESAM key pair generated successful")
  
  return nil
}

func startHandler(c *cli.Context) (error) {
  var err error
  var globData globDataType
  var loginContext *login.Context
  var usersCache caches.UsersAuth
  var waitLoops sync.WaitGroup
  
  mainCtx, mainCancel := context.WithCancel(context.Background())
  
  log.Println("Start logging")
  
  globData.DataEvents = make(chan bool, 1)
  globData.AccessReqSecret = c.String("access-req-secret")
  
  _, err = os.Stat(c.String("esam-key"))
  if os.IsNotExist(err) {
    err = keysconv.GenAndSaveKeyPair(c.String("esam-key"), c.String("esam-key") + ".pub", opts.KeySize, "")
    if err != nil {
      log.WithFields(log.Fields{"details": err}).Errorln("Failed to generate key pair")
      return err
    }
  }
  
  loginContext, err = login.MakeContext(c.String("esam-key"), c.String("dir-addr"), c.String("dir-port"), c.String("tls-ca-cert"), c.String("verify-key"), "")
  if err != nil {
    log.WithFields(log.Fields{"details": err}).Errorln("Failed to determine login context")
    return err
  }
  
  err = usersCache.Init("")
  if err != nil {
    log.WithFields(log.Fields{"details": err}).Errorln("Failed to init users cache")
    return err
  }
  
  waitLoops.Add(2)
  
  go dirConnLoop(mainCtx, &globData, loginContext, &usersCache, &waitLoops)
  go usersSetupLoop(mainCtx, &globData, &usersCache, &waitLoops)
  
  signalChan := make(chan os.Signal, 1)
  signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
  
  signalReceiver := <-signalChan
  log.Printf("Received signal '%v' - terminating", signalReceiver)
  
  mainCancel()
  
  waitLoops.Wait()
  
  log.Println("Stop logging")
  
  return nil
}

func sendAccessReq(globData *globDataType, loginContext *login.Context) (error) {
  var err error
  var dirConn *tls.Conn
  var accessReq data.AccessReq
  
  dirConn, err = tls.Dial("tcp", loginContext.DirAddr + ":" + loginContext.DirPort, &loginContext.TLSConfig)
  if err != nil {
    return err
  }
  defer dirConn.Close()
  
  accessReq.ESAMPubKey = loginContext.ESAMPubKey
  accessReq.Subject = data.AccessReqSubjectAgent
  accessReq.Name, err = os.Hostname()
  if err != nil {
    return err
  }
  
  err = requests.SendAccessReq(dirConn, &accessReq, globData.AccessReqSecret, opts.NetTimeout)
  if err != nil {
    return err
  }
  
  return nil
}

func dirConnLoop(ctx context.Context, globData *globDataType, loginContext *login.Context, usersCache *caches.UsersAuth, wait *sync.WaitGroup) {
  defer wait.Done()
  
  var err error
  var dirConn *tls.Conn
  var dirConnAllocated bool
  var updateUsersCacheTimer <-chan time.Time
  var noMsgTimer <-chan time.Time
  var noopTimer <-chan time.Time
  var accessRequestIsSended bool
  
  var usersListDB []data.UserDB
  
  freeLoopResources := func() {
    if dirConnAllocated {
      dirConn.Close()
      dirConnAllocated = false
    }
  }
  
  defer freeLoopResources()
  
  for {
    select {
      case <-ctx.Done(): {
        return
      }
      
      default: {
        freeLoopResources()
        
        dirConn, err = tls.Dial("tcp", loginContext.DirAddr + ":" + loginContext.DirPort, &loginContext.TLSConfig)
        if err != nil {
          log.WithFields(log.Fields{"details": err}).Errorln("Failed to connect to Director")
          break
        }
        
        dirConnAllocated = true
        
        err = requests.Auth(dirConn, &loginContext.ESAMPubKey, loginContext.Key, false, opts.NetTimeout)
        if err != nil {
          log.WithFields(log.Fields{"details": err}).Errorln("Login failed")
          
          if !accessRequestIsSended {
            sendAccessReq(globData, loginContext)
            accessRequestIsSended = true
          }
          
          break
        }
        
        log.Println("Login successful")
        
        noMsgTimer = time.After(opts.NoMsgThresholdTime)
        noopTimer = time.After(opts.NoopNoticePeriod)
        updateUsersCacheTimer = time.After(0)
        time.Sleep(1 * time.Millisecond)
        
authLoop:
        for {
          var msgIn []byte
          var msgOut []byte
          var msgInHeader netapi.MsgHeader
          
          sendReqListUsers := func(netTimeout time.Duration) (error) {
            var err error
            var userFilter data.User
            
            msgOut, err = netapi.BuildReqListUsers(&userFilter)
            if err != nil {
              return err
            }
            
            _, err = netmsg.Send(dirConn, msgOut[:], netTimeout)
            if err != nil {
              return err
            }
            
            return nil
          }
          
          sendNoop := func(netTimeout time.Duration) (error) {
            var err error
            
            msgOut, err = netapi.BuildNotice(netapi.NoticeTypeNoop)
            if err != nil {
              return err
            }
            
            _, err = netmsg.Send(dirConn, msgOut[:], netTimeout)
            if err != nil {
              return err
            }
            
            return nil
          }
          
          updateUsersCache := func() () {
            if len(usersListDB[:]) > 0 {
              log.Println("Update users cache")
              
              updateUsersCacheTimer = time.After(opts.UpdateUsersListPeriod)
              
              err = usersCache.Update(usersListDB[:], &loginContext.VerifyKey, opts.CPUUtilizationFactor)
              if err != nil {
                log.WithFields(log.Fields{"details": err}).Errorln("Failed to update users cache")
              } else {
                log.Println("Users cache update successful")
                select {
                  case globData.DataEvents <- true:
                  default: {
                    log.Errorln("Failed to send data event")
                  }
                }
              }
            }
          }
          
          select {
            case <-ctx.Done(): {
              return
            }
            
            case <-noMsgTimer: {
              log.WithFields(log.Fields{"details": err}).Errorln("Messages were missing more than the threshold time - reconnect")
              break authLoop
            }
            
            case <-noopTimer: {
              noopTimer = time.After(opts.NoopNoticePeriod)
              
              err = sendNoop(opts.NetTimeout)
              if err != nil {
                log.WithFields(log.Fields{"details": err}).Errorln("Failed to send noop notice")
                break authLoop
              }
            }
            
            case <-updateUsersCacheTimer: {
              updateUsersCacheTimer = time.After(opts.UpdateUsersListPeriod)
              
              log.Println("Send requests to refresh users cache")
              
              err = sendReqListUsers(opts.NetTimeout)
              if err != nil {
                log.WithFields(log.Fields{"details": err}).Errorln("Failed to send request to get list of users")
                break authLoop
              }
              
              log.Println("Successfully sent users cache update requests")
              
              usersListDB = []data.UserDB{}
            }
            
            default: {
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
              
              err = netapi.ParseMsgHeader(msgIn[:], &msgInHeader)
              if err != nil {
                log.WithFields(log.Fields{"details": err}).Errorln("Failed to parse message header")
                break authLoop
              }
              
              switch msgInHeader.Type {
                case netapi.MsgTypeReply: {
                  noMsgTimer = time.After(opts.NoMsgThresholdTime)
                  
                  switch msgInHeader.SubType {
                    case netapi.ReqTypeListUsers: {
                      usersListDB, err = netapi.ParseRepListUsers(msgIn[:])
                      if err != nil {
                        break authLoop
                      }
                      
                      updateUsersCache()
                    }
                    
                    default: {
                      log.WithFields(log.Fields{"details": err}).Errorln("Unsupported at this stage reply was received")
                      continue
                    }
                  }
                }
                
                case netapi.MsgTypeNotice: {
                  noMsgTimer = time.After(opts.NoMsgThresholdTime)
                  
                  switch msgInHeader.SubType {
                    case netapi.NoticeTypeNoop: {
                      //log.Println("NOOP")
                      continue
                    }
                    
                    case netapi.NoticeTypeUpdatedUsers: {
                      log.Println("Send requests to refresh users cache")
                      
                      err = sendReqListUsers(opts.NetTimeout)
                      if err != nil {
                        log.WithFields(log.Fields{"details": err}).Errorln("Failed to send request to get list of users")
                        break authLoop
                      }
                      
                      log.Println("Successfully sent users cache update requests")
                    }
                    
                    case netapi.NoticeTypeUpdatedNodes: {
                    }
                    
                    default: {
                      log.WithFields(log.Fields{"details": err}).Errorln("Unsupported at this stage notice was received")
                      continue
                    }
                  }
                }
                
                default: {
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

func usersSetupLoop(ctx context.Context, globData *globDataType, usersCache *caches.UsersAuth, wait *sync.WaitGroup) {
  defer wait.Done()
  
  var err error
  var usersSetupTimer <-chan time.Time
  var usersList []data.UserAuth
  
  usersSetupTimer = time.After(opts.UsersSetupPeriod)
  
  for {
    select {
      case <-ctx.Done(): {
        return
      }
      
      case <-globData.DataEvents: {
        usersCache.RLock()
          usersList = make([]data.UserAuth, len(usersCache.Get()))
          copy(usersList, usersCache.Get())
        usersCache.RUnlock()
        
        err = usersSetup(usersList[:])
        if err != nil {
          log.WithFields(log.Fields{"details": err}).Errorln("Failed to setup users")
        }
        
        usersSetupTimer = time.After(opts.UsersSetupPeriod)
      }
      
      case <-usersSetupTimer: {
        usersCache.RLock()
          usersList = make([]data.UserAuth, len(usersCache.Get()))
          copy(usersList, usersCache.Get())
        usersCache.RUnlock()
        
        err = usersSetup(usersList[:])
        if err != nil {
          log.WithFields(log.Fields{"details": err}).Errorln("Failed to setup users")
        }
        
        usersSetupTimer = time.After(opts.UsersSetupPeriod)
      }
    }
  }
}

func usersSetup(usersList []data.UserAuth) (error) {
  var err error
  
  log.Println("Processing users setup")
  
  log.Printf("Setup group %v", opts.UsersGroup)
  
  err = setup.GroupPresent(opts.UsersGroup, &setup.GroupPresentOpts{})
  if err != nil {
    return err
  }
  
  log.Printf("Setup group %v successfully", opts.UsersGroup)
  
  for index, _ := range usersList[:] {
    log.Printf("Processing user: %v", usersList[index].Name)
    
    processUser := func() (error) {
      var err error
      
      if usersList[index].TrustedData != types.True {
        return errors.New("No trust in user data")
      }
      
      err = types.TestSSHPublicKey(usersList[index].SSHPubKey)
      if err != nil && usersList[index].State == data.UserStateEnabled {
        usersList[index].State = data.UserStateSuspended
      }
      
      switch usersList[index].State {
        case data.UserStateDisabled: {
          err = setup.UserAbsent(usersList[index].Name, &setup.UserAbsentOpts{ Force: true, Remove: true })
          if err != nil {
            return err
          }
        }
        
        case data.UserStateSuspended: {
          err = setup.UserPresent(usersList[index].Name, &setup.UserPresentOpts{ExpireDate: "-1", Groups: []string{" "}, Password: "*", Shell: "/bin/false"})
          if err != nil {
            return err
          }
          
          err = setup.AuthorizedKeyAbsent(usersList[index].Name, nil, true)
          if err != nil {
            return err
          }
        }
        
        case data.UserStateEnabled: {
          var userOpts setup.UserPresentOpts
          
          userOpts.ExpireDate = " "
          userOpts.Gid = opts.UsersGroup
          userOpts.Password = usersList[index].PasswordHash
          userOpts.Shell = opts.UserShell
          if usersList[index].PasswordHash != "" && usersList[index].ElevatePrivileges == true {
            var availableGroups []string
            
            availableGroups, err = misc.LeaveAvailableGroups(opts.ElevatePrivilegesGroups)
            if err != nil {
              return err
            }
            
            userOpts.Groups = availableGroups
          } else {
            userOpts.Groups = []string{" "}
          }
          
          err = setup.UserPresent(usersList[index].Name, &userOpts)
          if err != nil {
            return err
          }
          
          err = setup.AuthorizedKeyPresent(usersList[index].Name, &types.AuthorizedKey{ Key: usersList[index].SSHPubKey, Options: []string{""}, Comment: "" }, true)
          if err != nil {
            return err
          }
        }
      }
      
      return nil
    }
    
    err = processUser()
    if err != nil {
      log.WithFields(log.Fields{"details": err}).Errorf("Processing user: %v failed", usersList[index].Name)
    } else {
      log.Printf("Processing user: %v successfully", usersList[index].Name)
    }
  }
  
  return nil
}

func cleanHandler(c *cli.Context) (error) {
  var err error
  var userNames []string
  var targetGroup *user.Group
  var targetUserNames []string
  var targetUserNamesInYAML []byte
  var deleteConfirm bool
  
  targetGroup, err = user.LookupGroup(opts.UsersGroup)
  if err != nil {
    ui.PrintError("Failed to obtain target group data: %v", err, opts.UsersGroup)
    return err
  }
  
  userNames, err = users.ListNames()
  if err != nil {
    ui.PrintError("Failed to obtain users list", err)
    return err
  }
  
  targetUserNames = make([]string, 0)
  
  for _, userName := range userNames[:] {
    var targetUser *user.User
    
    targetUser, err = user.Lookup(userName)
    if err != nil {
      ui.PrintError("Failed to obtain user data: %v", err, userName)
      continue
    }
    
    if targetUser.Gid == targetGroup.Gid {
      targetUserNames = append(targetUserNames, userName)
    }
  }
  
  if len(targetUserNames[:]) == 0 {
    ui.PrintInfo("Target users list is empty")
    return nil
  }
  
  type targetUserNamesWrap struct {
    TargetUserNames []string `yaml:"Target users"`
  }
  
  targetUserNamesWrapper := targetUserNamesWrap{ TargetUserNames: targetUserNames[:] }
  
  targetUserNamesInYAML, err = yaml.Marshal(targetUserNamesWrapper)
  if err != nil {
    return err
  }
  
  fmt.Printf("%v", string(targetUserNamesInYAML[:]))
  
  deleteConfirm, err = ui.AskYesNo("Delete all target users?")
  if err != nil {
    ui.PrintError("Failed to read answer", err)
    return err
  }
  
  if deleteConfirm {
    for _, targetUserName := range targetUserNames[:] {
      ui.PrintInfo("Delete user: %v", targetUserName)
      
      err = setup.UserAbsent(targetUserName, &setup.UserAbsentOpts{ Force: true, Remove: true })
      if err != nil {
        ui.PrintError("Delete user: %v failed", err, targetUserName)
        continue
      }
    }
  }
  
  return nil
}
