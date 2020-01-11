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

package setup

import (
  "fmt"
  "os"
  "os/user"
  "io/ioutil"
  "path"
  "testing"
)

import (
  "esam/src/types"
  "esam/src/opts"
)

const (
  userName = "esam_user"
)

func Test(t *testing.T) {
  var err error
  var userInfo *user.User
  var userGroupIds []string
  var fileContent []byte
  
  err = GroupPresent("esam", &GroupPresentOpts{})
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present group", err)
    os.Exit(1)
  }
  
  err = UserPresent(userName, &UserPresentOpts{Gid: "esam"})
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present user", err)
    os.Exit(1)
  }
  
  userInfo, err = user.Lookup(userName)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to get user info", err)
    os.Exit(1)
  }
  userGroupIds, _ = userInfo.GroupIds()
  fmt.Printf("userInfo = %+v\nuserGroupIds = %+v\n", userInfo, userGroupIds)
  
  err = AuthorizedKeyPresent(userName, &types.AuthorizedKey{ Key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJzQq9fiCWSEo2kR46nFkOTIsgXnKggleO3BNrj6caxg8qE/V+RihJOISuSm98iQD437NAZEdZOmixk4KNTdDaONaw5YjtLY9XGltv7G8MyIuNjn5F724ebyofl3I5z+Jn9YOecLG1fsBwaPN62vhzQLZd08cttIlTRTIyfBlrhuZK+mPU2fqyuzkPqXt6Poa+ys8i/+WD6B6C3tLyW32DmObbW8wSXZSPatVzpcC+qXbXOjs+ZA0L71SwuQkFrMrnxtLG/5sbsXUuJunNfRJlw6i8o3lDAzhmreVXuow+koAVVgJaG18LmDPSxwgxOkcrBVXsUQ9mk8WUGnTTZKNRCvHLk5GjHryNlmPS1Tjr1ZPspR5+lnlGW1qdMwECvBNePAPSoTSO7L2wAsJhc4PXN8z94WTbzQsAf4PaEjKS8QP5s9WRGACVH1/wKRcMDmutj/g5o1G4yiXcYbtsFs4UxFOnbwV6mNn7qM038U2Sae/HVG83XRleey9SWoYc0G8= user@localhost.localdomain", Options: []string{""}, Comment: "user@localhost.localdomain" }, false)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present authorized key", err)
    os.Exit(1)
  }
  
  err = AuthorizedKeyPresent(userName, &types.AuthorizedKey{ Key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4J5/ZoG+CjkJwmSx/x0yrDhz81rnOF7aWLd2OcZ+NJiABSW+lSnfvQrLkP/BLHzW1H/2SYCCrdsH2Ak+Tw1xQHvoHeuPKS5/9I3ccm+euDlL4/+a1XjqD5PTbAyI97RsyyKuzzsffEz0rQ/Fd2GVA5xx9hc533Wj0OBvEneH+ppgHmRwuabh6xECKYPrKKiGPq2KcMaxOpcwFouA3p/STWpTIoocmM3kf81q+haYB/GAXjbIQrgJctZVwFbBLErhVD6ICgxcNzvhEUEl6GoUvaheCfcNxKubj0sPQcCRir7cwwCMkeKokqX5Xw6aSn5VoONU0bxd+MFivffs7pxlIOZv3VwTroYZBFIG2X5LwauZTQw9KlI5JSjqsS4FL4byiCqJ3yWK0ZI3C7x42WqMgEhJ7jlD639RrdOXNZjBOs27WZoNV2lXUHr/0EkkWm5qfZRmKbIyzgJz7c87NgzcqtvkpuUwPdKO9x8hCkZzTHiCGOFXxR3zX1i1Rq0ik9sc= user@localhost.localdomain", Options: []string{""}, Comment: "user@localhost.localdomain" }, false)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present authorized key", err)
    os.Exit(1)
  }
  
  err = AuthorizedKeyPresent(userName, &types.AuthorizedKey{ Key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBLiPPjPEGtXH4wtxO4pJDnF+T2xKGOcduj2VJakMkOxzzbIi8EWAPoSLVnGVN0jsDSS9nin4zLGSArbz8zS2ifCIKML9MhM+faeNPCm+6qO/5Z1a+X21pTQPhVFuRkDNBy+qdPZfpY7vBtOZPg5L1smTl1fx5NkXo6ecuVHmiMpOfhtOQHNKSYjtW1RQqWmHWL9jzDIFs3ZTrtP9Uuc/f1+EwRxlWLhEdT0NkQeDAYS2YxR0+/iDYR0lNQrrtU3YzAKZRHpD4jkyNSeLDGc5quLi9FppnM0MiV8J5K9QrP7qXxbnSjcudVyRZjVZiHW/apJiu5GQ0/3gM7/JddnjFrgf1rGJqpkkPZ+7qPL9TfgGgmjJTyMVQFnK1uSbVXZSMKvw1fb5QDM9/32+RfbMaOks5NAtN8csXdnnOlI4upvmpLHZYdgNyq+JNNUvoYBXm5jftTrih8b3emIL11Hb5hGWpFC4sP3LxXnEd8TfixUPdkhFCPIIXhBLmTFi6nXc=", Options: []string{"command=\"/bin/bash\""}, Comment: "user@localhost.localdomain" }, false)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present authorized key", err)
    os.Exit(1)
  }
  
  fileContent, err = ioutil.ReadFile(path.Join(userInfo.HomeDir, opts.SSHDirName, opts.AuthorizedKeysFileName))
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to read authorized key", err)
    os.Exit(1)
  }
  
  fmt.Printf("File content:\n%s\n", string(fileContent))
  
  
  err = AuthorizedKeyAbsent(userName, &types.AuthorizedKey{ Key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4J5/ZoG+CjkJwmSx/x0yrDhz81rnOF7aWLd2OcZ+NJiABSW+lSnfvQrLkP/BLHzW1H/2SYCCrdsH2Ak+Tw1xQHvoHeuPKS5/9I3ccm+euDlL4/+a1XjqD5PTbAyI97RsyyKuzzsffEz0rQ/Fd2GVA5xx9hc533Wj0OBvEneH+ppgHmRwuabh6xECKYPrKKiGPq2KcMaxOpcwFouA3p/STWpTIoocmM3kf81q+haYB/GAXjbIQrgJctZVwFbBLErhVD6ICgxcNzvhEUEl6GoUvaheCfcNxKubj0sPQcCRir7cwwCMkeKokqX5Xw6aSn5VoONU0bxd+MFivffs7pxlIOZv3VwTroYZBFIG2X5LwauZTQw9KlI5JSjqsS4FL4byiCqJ3yWK0ZI3C7x42WqMgEhJ7jlD639RrdOXNZjBOs27WZoNV2lXUHr/0EkkWm5qfZRmKbIyzgJz7c87NgzcqtvkpuUwPdKO9x8hCkZzTHiCGOFXxR3zX1i1Rq0ik9sc= user@localhost.localdomain", Options: []string{""}, Comment: "user@localhost.localdomain" }, false)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to absent authorized key", err)
    os.Exit(1)
  }
  
  fileContent, err = ioutil.ReadFile(path.Join(userInfo.HomeDir, opts.SSHDirName, opts.AuthorizedKeysFileName))
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to read authorized key", err)
    os.Exit(1)
  }
  
  fmt.Printf("File content:\n%s\n", string(fileContent))
  
  
  err = AuthorizedKeyPresent(userName, &types.AuthorizedKey{ Key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBLiPPjPEGtXH4wtxO4pJDnF+T2xKGOcduj2VJakMkOxzzbIi8EWAPoSLVnGVN0jsDSS9nin4zLGSArbz8zS2ifCIKML9MhM+faeNPCm+6qO/5Z1a+X21pTQPhVFuRkDNBy+qdPZfpY7vBtOZPg5L1smTl1fx5NkXo6ecuVHmiMpOfhtOQHNKSYjtW1RQqWmHWL9jzDIFs3ZTrtP9Uuc/f1+EwRxlWLhEdT0NkQeDAYS2YxR0+/iDYR0lNQrrtU3YzAKZRHpD4jkyNSeLDGc5quLi9FppnM0MiV8J5K9QrP7qXxbnSjcudVyRZjVZiHW/apJiu5GQ0/3gM7/JddnjFrgf1rGJqpkkPZ+7qPL9TfgGgmjJTyMVQFnK1uSbVXZSMKvw1fb5QDM9/32+RfbMaOks5NAtN8csXdnnOlI4upvmpLHZYdgNyq+JNNUvoYBXm5jftTrih8b3emIL11Hb5hGWpFC4sP3LxXnEd8TfixUPdkhFCPIIXhBLmTFi6nXc=", Options: []string{"command=\"/bin/bash\""}, Comment: "user@localhost.localdomain" }, true)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present authorized key", err)
    os.Exit(1)
  }
  
  fileContent, err = ioutil.ReadFile(path.Join(userInfo.HomeDir, opts.SSHDirName, opts.AuthorizedKeysFileName))
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to read authorized key", err)
    os.Exit(1)
  }
  
  fmt.Printf("File content:\n%s\n", string(fileContent))
  
  
  err = AuthorizedKeyAbsent(userName, nil, true)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to absent authorized key", err)
    os.Exit(1)
  }
  
  fileContent, err = ioutil.ReadFile(path.Join(userInfo.HomeDir, opts.SSHDirName, opts.AuthorizedKeysFileName))
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to read authorized key", err)
    os.Exit(1)
  }
  
  fmt.Printf("File content:\n%s\n", string(fileContent))
  
  
  err = UserPresent(userName, &UserPresentOpts{ExpireDate: "-1", Groups: []string{"adm", "sys"}})
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present user", err)
    os.Exit(1)
  }
  
  userInfo, err = user.Lookup(userName)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to get user info", err)
    os.Exit(1)
  }
  userGroupIds, _ = userInfo.GroupIds()
  fmt.Printf("userInfo = %+v\nuserGroupIds = %+v\n", userInfo, userGroupIds)
  
  err = UserPresent(userName, &UserPresentOpts{ExpireDate: "-1", Groups: []string{" "}})
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present user", err)
    os.Exit(1)
  }
  
  userInfo, err = user.Lookup(userName)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to get user info", err)
    os.Exit(1)
  }
  userGroupIds, _ = userInfo.GroupIds()
  fmt.Printf("userInfo = %+v\nuserGroupIds = %+v\n", userInfo, userGroupIds)
  
  err = UserPresent(userName, &UserPresentOpts{ExpireDate: "0"})
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to present user", err)
    os.Exit(1)
  }
  
  userInfo, err = user.Lookup(userName)
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to get user info", err)
    os.Exit(1)
  }
  userGroupIds, _ = userInfo.GroupIds()
  fmt.Printf("userInfo = %+v\nuserGroupIds = %+v\n", userInfo, userGroupIds)
  
  err = UserAbsent(userName, &UserAbsentOpts{Force: true, Remove: true})
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to absent user", err)
    os.Exit(1)
  }
  
  userInfo, err = user.Lookup(userName)
  if err == nil {
    fmt.Printf("%v. Details: %v\n", "Success to get user info", err)
    os.Exit(1)
  }
  
  err = GroupAbsent("esam")
  if err != nil {
    fmt.Printf("%v. Details: %v\n", "Failed to absent group", err)
    os.Exit(1)
  }
}
