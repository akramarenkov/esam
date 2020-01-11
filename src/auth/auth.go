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

package auth

/*
Authentication
Authorization
Authenticity check
*/

import (
  "errors"
)

import (
  "esam/src/data"
  "esam/src/db"
  "esam/src/netapi"
)

const (
  SubjectUnknown = iota
  SubjectEngineer
  SubjectSecAdmin
  SubjectOwner
  SubjectUDS
  SubjectAgent
)

type Context struct {
  SubjectType int
  SubjectData interface {}
}

var (
  userRoleToSubjectType = map[string]int {
    data.UserRoleEngineer: SubjectEngineer,
    data.UserRoleSecAdmin: SubjectSecAdmin,
    data.UserRoleOwner: SubjectOwner,
  }
)

var (
  userRoleLevels = map[string]int {
    data.UserRoleEngineer: 0,
    data.UserRoleSecAdmin: 1,
    data.UserRoleOwner: 2,
  }
)

var (
  listAccessReqsAccessRightsMap = map[int]bool {
    SubjectEngineer: true,
    SubjectSecAdmin: true,
    SubjectOwner: true,
    SubjectUDS: true,
  }
  
  delAccessReqAccessRightsMap = map[int]bool {
    SubjectSecAdmin: true,
    SubjectOwner: true,
    SubjectUDS: true,
  }
  
  addUserAccessRightsMap = map[int]map[string]bool {
    SubjectSecAdmin: map[string]bool {
      data.UserRoleEngineer: true,
    },
    SubjectOwner: map[string]bool {
      data.UserRoleEngineer: true,
      data.UserRoleSecAdmin: true,
    },
    SubjectUDS: map[string]bool {
      data.UserRoleEngineer: true,
      data.UserRoleSecAdmin: true,
      data.UserRoleOwner: true,
    },
  }
  
  changePasswordAccessRightsMap = map[int]bool {
    SubjectEngineer: true,
    SubjectSecAdmin: true,
    SubjectOwner: true,
  }
  
  listUsersAccessRightsMap = map[int]bool {
    SubjectEngineer: true,
    SubjectSecAdmin: true,
    SubjectOwner: true,
    SubjectUDS: true,
    SubjectAgent: true,
  }
  
  getAuthUserDataAccessRightsMap = map[int]bool {
    SubjectUDS: true,
  }
  
  addNodeAccessRightsMap = map[int]bool {
    SubjectSecAdmin: true,
    SubjectOwner: true,
    SubjectUDS: true,
  }
  
  listNodesAccessRightsMap = map[int]bool {
    SubjectEngineer: true,
    SubjectSecAdmin: true,
    SubjectOwner: true,
    SubjectUDS: true,
  }
  
  findInNodesCacheAccessRightsMap = map[int]bool {
    SubjectUDS: true,
  }
  
  getDirConnSettingsAccessRightsMap = map[int]bool {
    SubjectUDS: true,
  }
)

func IdentifySubject(subjectESAMPubKey *data.ESAMPubKey, db *db.Desc) (*Context, error) {
  var err error
  
  var authContext *Context
  
  var nodeFilter data.Node
  var nodesDBList []data.NodeDB
  var userFilter data.User
  var usersDBList []data.UserDB
  
  if subjectESAMPubKey == nil {
    return nil, errors.New("ESAM pub key can't be nil")
  }
  
  if db == nil {
    return nil, errors.New("DB descriptor can't be nil")
  }
  
  err = subjectESAMPubKey.Test(data.ToleratesEmptyFieldsNo)
  if err != nil {
    return nil, err
  }
  
  nodeFilter.ESAMPubKey = (*subjectESAMPubKey)
  userFilter.ESAMPubKey = (*subjectESAMPubKey)
  
  nodesDBList, err = db.ListNodes(&nodeFilter)
  if err != nil {
    return nil, err
  }
  
  usersDBList, err = db.ListUsers(&userFilter)
  if err != nil {
    return nil, err
  }
  
  if len(nodesDBList) == 0 && len(usersDBList) == 0 {
    return nil, errors.New("Provided ESAM pub key not found - unauthenticated")
  }
  
  if len(nodesDBList) > 0 && len(usersDBList) > 0 {
     return nil, errors.New("Provided ESAM pub key found in nodes and users lists - integrity violation")
  }
  
  if len(nodesDBList) > 1 {
     return nil, errors.New("Provided ESAM pub key found in multiplicity nodes - integrity violation")
  }
  
  if len(usersDBList) > 1 {
     return nil, errors.New("Provided ESAM pub key found in multiplicity users - integrity violation")
  }
  
  if len(nodesDBList) == 1 {
    err = nodesDBList[0].Node.Test(data.ToleratesEmptyFieldsNo)
    if err != nil {
      return nil, err
    }
    
    if nodesDBList[0].Node.ESAMPubKey.EqualConstantTime(subjectESAMPubKey) != true {
      return nil, errors.New("Provided ESAM pub key found in db, but not equal to the found pub key")
    }
    
    authContext = new(Context)
    
    authContext.SubjectType = SubjectAgent
    authContext.SubjectData = nodesDBList[0].Node
    
    return authContext, nil
  }
  
  if len(usersDBList) == 1 {
    err = usersDBList[0].User.Test(data.ToleratesEmptyFieldsNo)
    if err != nil {
      return nil, err
    }
    
    if usersDBList[0].User.ESAMPubKey.EqualConstantTime(subjectESAMPubKey) != true {
      return nil, errors.New("Provided ESAM pub key found in db, but not equal to the found pub key")
    }
    
    if usersDBList[0].User.State != data.UserStateEnabled {
      return nil, errors.New("User not in enabled state")
    }
    
    authContext = new(Context)
    
    authContext.SubjectType = userRoleToSubjectType[usersDBList[0].User.Role]
    authContext.SubjectData = usersDBList[0].User
    
    return authContext, nil
  }
  
  return nil, errors.New("Unknown error")
}

func CheckSubjectAccessRights(authContext *Context, newObject interface {}, oldObject interface {}, reqType string) (bool, error) {
  switch reqType {
    case netapi.ReqTypeAddAccessReq: {
      return true, nil
    }
    
    case netapi.ReqTypeAuth: {
      return true, nil
    }
    
    case netapi.ReqTypeListAccessReqs: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return listAccessReqsAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeDelAccessReq: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return delAccessReqAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeAddUser: {
      var newObjectUser data.UserDB
      var castOk bool
      
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      if newObject == nil {
        return false, errors.New("New object can't be nil")
      }
      
      newObjectUser, castOk = newObject.(data.UserDB)
      if !castOk {
        return false, errors.New("Failed to cast new object to user data")
      }
      
      return addUserAccessRightsMap[authContext.SubjectType][newObjectUser.User.Role], nil
    }
    
    case netapi.ReqTypeUpdateUser: {
      var newObjectUser data.UserDB
      var oldObjectUser data.UserDB
      var subjectUser data.User
      
      var castOk bool
      
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      if newObject == nil {
        return false, errors.New("New object can't be nil")
      }
      
      if oldObject == nil {
        return false, errors.New("Old object can't be nil")
      }
      
      newObjectUser, castOk = newObject.(data.UserDB)
      if !castOk {
        return false, errors.New("Failed to cast new object to user data")
      }
      
      oldObjectUser, castOk = oldObject.(data.UserDB)
      if !castOk {
        return false, errors.New("Failed to cast old object to user data")
      }
      
      if authContext.SubjectType == SubjectUDS {
        return true, nil
      }
      
      /* subjectUser for SubjectUDS not defined */
      subjectUser, castOk = authContext.SubjectData.(data.User)
      if !castOk {
        return false, errors.New("Failed to cast subject data to user data")
      }
      
      if oldObjectUser.User.ESAMPubKey.Equal(&subjectUser.ESAMPubKey) == true {
        if authContext.SubjectType == SubjectOwner {
          return true, nil
        }
      }
      
      return addUserAccessRightsMap[authContext.SubjectType][newObjectUser.User.Role] && addUserAccessRightsMap[authContext.SubjectType][oldObjectUser.User.Role], nil
    }
    
    case netapi.ReqTypeChangePassword: {
      var newObjectUser data.UserDB
      var oldObjectUser data.UserDB
      var subjectUser data.User
      
      var castOk bool
      
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      if newObject == nil {
        return false, errors.New("New object can't be nil")
      }
      
      if oldObject == nil {
        return false, errors.New("Old object can't be nil")
      }
      
      newObjectUser, castOk = newObject.(data.UserDB)
      if !castOk {
        return false, errors.New("Failed to cast new object to user data")
      }
      
      oldObjectUser, castOk = oldObject.(data.UserDB)
      if !castOk {
        return false, errors.New("Failed to cast old object to user data")
      }
      
      if authContext.SubjectType == SubjectUDS {
        return false, errors.New("Authentication required but used UDS-connection")
      }
      
      /* subjectUser for SubjectUDS not defined */
      subjectUser, castOk = authContext.SubjectData.(data.User)
      if !castOk {
        return false, errors.New("Failed to cast subject data to user data")
      }
      
      if oldObjectUser.User.ESAMPubKey.Equal(&subjectUser.ESAMPubKey) == true {
        if oldObjectUser.EqualWithIgnoreFields(&newObjectUser, map[string]bool{"PasswordHash": true, "PasswordHashSign": true}) == true {
          /* Additional checks for security reasons, because there is no 100% trust to EqualWithIgnoreFields function */
          if oldObjectUser.User.Role == newObjectUser.User.Role {
            if oldObjectUser.User.ElevatePrivileges == newObjectUser.User.ElevatePrivileges {
              return changePasswordAccessRightsMap[authContext.SubjectType], nil
            }
          }
        }
      }
      
      return false, errors.New("Unexpected behavior")
    }
    
    case netapi.ReqTypeListUsers: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return listUsersAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeGetAuthUserData: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return getAuthUserDataAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeDelUser: {
      var oldObjectUser data.UserDB
      var castOk bool
      
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      if oldObject == nil {
        return false, errors.New("Old object can't be nil")
      }
      
      oldObjectUser, castOk = oldObject.(data.UserDB)
      if !castOk {
        return false, errors.New("Failed to cast old object to user data")
      }
      
      return addUserAccessRightsMap[authContext.SubjectType][oldObjectUser.User.Role], nil
    }
    
    case netapi.ReqTypeAddNode: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return addNodeAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeUpdateNode: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return addNodeAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeListNodes: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return listNodesAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeFindInNodesCache: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return findInNodesCacheAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeDelNode: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return addNodeAccessRightsMap[authContext.SubjectType], nil
    }
    
    case netapi.ReqTypeGetDirConnSettings: {
      if authContext == nil {
        return false, errors.New("Auth context can't be nil")
      }
      
      return getDirConnSettingsAccessRightsMap[authContext.SubjectType], nil
    }
    
    default: {
      return false, errors.New("Unsupported request type")
    }
  }
  
  return false, errors.New("Unexpected behavior")
}

func CheckUserDataAuthenticity(user *data.UserDB, usersList []data.UserDB, verifyKey *data.ESAMPubKey) (bool, error) {
  var err error
  var userTmp *data.UserDB
  
  if user == nil {
    return false, errors.New("User data can't be nil")
  }
  
  if len(usersList) == 0 {
    return false, errors.New("Users list can't be empty")
  }
  
  if verifyKey == nil {
    return false, errors.New("Verify key can't be nil")
  }
  
  if verifyKey.Len() < 1 {
    return false, errors.New("Verify key can't be empty")
  }
  
  userTmp = user
  
  for level := userRoleLevels[user.User.Role]; level <= userRoleLevels[data.UserRoleOwner]; level++ {
    
    err = userTmp.Verify(map[string]bool{"PasswordHash": true})
    if err != nil {
      return false, err
    }
    
    if userTmp.UserSign.SignSubject.Equal(verifyKey) == false {
      var userOfNewLevelFound bool
      
      userOfNewLevelFound = false
      for index, _ := range usersList {
        if usersList[index].User.ESAMPubKey.Equal(&userTmp.UserSign.SignSubject) == true {
          if userRoleLevels[usersList[index].User.Role] > userRoleLevels[userTmp.User.Role] {
            if usersList[index].User.State == data.UserStateEnabled {
              userTmp = &usersList[index]
              userOfNewLevelFound = true
              break
            }
          }
        }
      }
      
      if userOfNewLevelFound == false {
        return false, errors.New("Trust chain interrupted")
      }
    } else {
      return true, nil
    }
  }
  
  return false, errors.New("Unknown error")
}

func CheckNodeDataAuthenticity(node *data.NodeDB, usersList []data.UserDB, verifyKey *data.ESAMPubKey) (bool, error) {
  var err error
  var signer *data.UserDB
  var canTrustSigner bool
  
  if node == nil {
    return false, errors.New("Node data can't be nil")
  }
  
  if usersList == nil {
    return false, errors.New("Users list can't be nil")
  }
  
  if verifyKey == nil {
    return false, errors.New("Verify key can't be nil")
  }
  
  if verifyKey.Len() < 1 {
    return false, errors.New("Verify key can't be empty")
  }
  
  signer = nil
  for index, _ := range usersList {
    if usersList[index].User.ESAMPubKey.Equal(&node.NodeSign.SignSubject) == true {
      signer = &usersList[index]
      break
    }
  }
  
  if signer == nil {
    return false, errors.New("Signer not found")
  }
  
  if userRoleLevels[signer.User.Role] < userRoleLevels[data.UserRoleSecAdmin] {
    return false, errors.New("Signer does not have authority to sign")
  }
  
  if signer.User.State != data.UserStateEnabled {
    return false, errors.New("Signer not in enabled state")
  }
  
  canTrustSigner, err = CheckUserDataAuthenticity(signer, usersList, verifyKey)
  if err != nil {
    return false, err
  }
  
  if canTrustSigner == true {
    return true, nil
  } else {
    return false, errors.New("Can't trust signer")
  }
  
  return false, errors.New("Unknown error")
}
