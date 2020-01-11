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

package sqlqb

import (
  "errors"
  "strconv"
  "reflect"
)

/*
SQL query build(-er)

Example:

type User struct {
  Key string `db:"key"`
  Name string `db:"name"`
  Role string `db:"role"`
}

var user User
var qb sqlqb.QB

user = User{"somekey", "somename", "somerole"}

qb.Begin(`INSERT INTO users`, "db")
qb.ValuesFromStruct(user)

For package sql use:
.Exec(qb.Query, qb.Args...)

where:
qb.Query = INSERT INTO users (key, name, role) VALUES($1, $2, $3)
qb.Args = [somekey somename somerole]

For package sqlx use:
.NamedExec(qb.QueryX, user)

where:
qb.QueryX = INSERT INTO users (key, name, role) VALUES(:key, :name, :role)


Test values:
fmt.Printf("qb.Query = %+v\nqb.QueryX = %+v\nqb.Args = %+v\nqb.ArgsX = %+v\n", qb.Query, qb.QueryX, qb.Args, qb.ArgsX)
*/

type QB struct {
  Query string
  QueryX string
  Args []interface{}
  ArgsX map[string]interface{}
  
  baseQuery string
  tagKey string
  argsCount uint64
  beginStagePassed bool
  callLevel uint64
  suppString string
  suppStringX string
}

func (qb *QB) Begin(baseQuery string, tagKey string) (error) {
  if qb == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if baseQuery == "" {
    return errors.New("Base query was empty")
  }
  
  if tagKey == "" {
    return errors.New("Field tag key was empty")
  }
  
  qb.Query = ""
  qb.QueryX = ""
  
  qb.Args = make([]interface{}, 0)
  qb.ArgsX = make(map[string]interface{})
  
  qb.baseQuery = baseQuery
  qb.tagKey = tagKey
  qb.argsCount = 0
  qb.beginStagePassed = false
  qb.callLevel = 0
  qb.suppString = ""
  qb.suppStringX = ""
  
  return nil
}

func (qb *QB) WhereAndFromStruct(structIn interface{}) (error) {
  var err error
  var structInReflectValue reflect.Value
  var fieldReflectValue reflect.Value
  var field reflect.StructField
  var fieldIsFull bool
  var fieldTag string
  var bindVar string
  
  if qb == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if structIn == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  structInReflectValue = reflect.ValueOf(structIn)
  
  if !structInReflectValue.IsValid() {
    return errors.New("Struct value is invalid")
  }
  
  if structInReflectValue.Kind() == reflect.Ptr {
    if structInReflectValue.IsNil() {
      return errors.New("Struct pointer is nil")
    }
    
    structInReflectValue = structInReflectValue.Elem()
    
    if !structInReflectValue.IsValid() {
      return errors.New("Struct value is invalid")
    }
  }
  
  if structInReflectValue.Kind() != reflect.Struct {
    return errors.New("Input variable was not Struct")
  }
  
  for index := 0; index < structInReflectValue.NumField(); index++ {
    fieldReflectValue = structInReflectValue.Field(index)
    field = structInReflectValue.Type().Field(index)
    
    switch fieldReflectValue.Kind() {
      case reflect.Struct: {
        qb.callLevel++
        err = qb.WhereAndFromStruct(fieldReflectValue.Interface())
        qb.callLevel--
        if err != nil {
          return err
        }
      }
      
      case reflect.Array, reflect.Map, reflect.Slice, reflect.String: {
        if fieldReflectValue.Len() > 0 {
          fieldIsFull = true
        } else {
          fieldIsFull = false
        }
      }
      
      default: {
        fieldIsFull = false
      }
    }
    
    fieldTag = field.Tag.Get(qb.tagKey)
    
    if fieldIsFull && fieldTag != "" {
      qb.argsCount++
      
      if qb.beginStagePassed == false {
        qb.Query += " WHERE "
        qb.QueryX += " WHERE "
        qb.beginStagePassed = true
      } else {
        qb.Query += " AND "
        qb.QueryX += " AND "
      }
      
      bindVar = strconv.FormatUint(qb.argsCount, 10)
      
      qb.Query += fieldTag + "=$" + bindVar
      qb.QueryX += fieldTag + "=:" + fieldTag
      qb.Args = append(qb.Args, fieldReflectValue.Interface())
      qb.ArgsX[fieldTag] = fieldReflectValue.Interface()
    }
  }
  
  if qb.callLevel == 0 {
    qb.Query = qb.baseQuery + qb.Query
    qb.QueryX = qb.baseQuery + qb.QueryX
  }
  
  return nil
}

func (qb *QB) ValuesFromStruct(structIn interface{}) (error) {
  var err error
  var structInReflectValue reflect.Value
  var fieldReflectValue reflect.Value
  var field reflect.StructField
  var fieldTag string
  var bindVar string
  
  if qb == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if structIn == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  structInReflectValue = reflect.ValueOf(structIn)
  
  if !structInReflectValue.IsValid() {
    return errors.New("Struct value is invalid")
  }
  
  if structInReflectValue.Kind() == reflect.Ptr {
    if structInReflectValue.IsNil() {
      return errors.New("Struct pointer is nil")
    }
    
    structInReflectValue = structInReflectValue.Elem()
    
    if !structInReflectValue.IsValid() {
      return errors.New("Struct value is invalid")
    }
  }
  
  if structInReflectValue.Kind() != reflect.Struct {
    return errors.New("Input variable was not Struct")
  }
  
  for index := 0; index < structInReflectValue.NumField(); index++ {
    fieldReflectValue = structInReflectValue.Field(index)
    field = structInReflectValue.Type().Field(index)
    
    if fieldReflectValue.Kind() == reflect.Struct {
      qb.callLevel++
      err = qb.ValuesFromStruct(fieldReflectValue.Interface())
      qb.callLevel--
      if err != nil {
        return err
      }
    }
    
    fieldTag = field.Tag.Get(qb.tagKey)
    
    if fieldTag != "" {
      qb.argsCount++
      
      if qb.beginStagePassed == false {
        qb.Query += " VALUES("
        qb.QueryX += " VALUES("
        qb.suppString += " ("
        qb.beginStagePassed = true
      } else {
        qb.Query += ", "
        qb.QueryX += ", "
        qb.suppString += ", "
      }
      
      bindVar = strconv.FormatUint(qb.argsCount, 10)
      
      qb.Query += "$" + bindVar
      qb.QueryX += ":" + fieldTag
      qb.suppString += fieldTag
      qb.Args = append(qb.Args, fieldReflectValue.Interface())
    }
  }
  
  if qb.callLevel == 0 && qb.argsCount > 0 {
    qb.Query += ")"
    qb.QueryX += ")"
    qb.suppString += ")"
    
    qb.Query = qb.baseQuery + qb.suppString + qb.Query
    qb.QueryX = qb.baseQuery + qb.suppString + qb.QueryX
  }
  
  return nil
}

func (qb *QB) SetWhereFromStruct(structIn interface{}, whereStruct interface{}, setEmpty bool) (error) {
  var err error
  var structInReflectValue reflect.Value
  var fieldReflectValue reflect.Value
  var field reflect.StructField
  var fieldIsFull bool
  var fieldTag string
  var bindVar string
  var qbWhere QB
  
  if qb == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if structIn == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  structInReflectValue = reflect.ValueOf(structIn)
  
  if !structInReflectValue.IsValid() {
    return errors.New("Struct value is invalid")
  }
  
  if structInReflectValue.Kind() == reflect.Ptr {
    if structInReflectValue.IsNil() {
      return errors.New("Struct pointer is nil")
    }
    
    structInReflectValue = structInReflectValue.Elem()
    
    if !structInReflectValue.IsValid() {
      return errors.New("Struct value is invalid")
    }
  }
  
  if structInReflectValue.Kind() != reflect.Struct {
    return errors.New("Input variable was not Struct")
  }
  
  if whereStruct != nil {
    err = qbWhere.Begin(" ", qb.tagKey)
    if err != nil {
      return err
    }
    
    err = qbWhere.WhereAndFromStruct(whereStruct)
    if err != nil {
      return err
    }
    
    qb.argsCount = qbWhere.argsCount
  }
    
  for index := 0; index < structInReflectValue.NumField(); index++ {
    fieldReflectValue = structInReflectValue.Field(index)
    field = structInReflectValue.Type().Field(index)
    
    switch fieldReflectValue.Kind() {
      case reflect.Struct: {
        qb.callLevel++
        err = qb.SetWhereFromStruct(fieldReflectValue.Interface(), nil, setEmpty)
        qb.callLevel--
        if err != nil {
          return err
        }
      }
      
      case reflect.Array, reflect.Map, reflect.Slice, reflect.String: {
        if fieldReflectValue.Len() > 0 {
          fieldIsFull = true
        } else {
          fieldIsFull = false
        }
      }
      
      default: {
        fieldIsFull = false
      }
    }
    
    if setEmpty {
      fieldIsFull = true
    }
    
    fieldTag = field.Tag.Get(qb.tagKey)
    
    if fieldIsFull && fieldTag != "" {
      qb.argsCount++
      bindVar = strconv.FormatUint(qb.argsCount, 10)
      
      if qb.beginStagePassed == false {
        qb.Query += " SET "
        qb.QueryX += " SET "
        qb.beginStagePassed = true
      } else {
        qb.Query += ", "
        qb.QueryX += ", "
      }
      
      qb.Query += fieldTag + "=$" + bindVar
      qb.QueryX += fieldTag + "=:" + fieldTag + "_updated"
      qb.Args = append(qb.Args, fieldReflectValue.Interface())
      qb.ArgsX[fieldTag + "_updated"] = fieldReflectValue.Interface()
    }
  }
  
  if qb.callLevel == 0 {
    qb.Query = qb.baseQuery + qb.Query + qbWhere.Query
    qb.QueryX = qb.baseQuery + qb.QueryX + qbWhere.QueryX
    qb.Args = append(qb.Args, qbWhere.Args)
    for key, _ := range qbWhere.ArgsX {
      qb.ArgsX[key] = qbWhere.ArgsX[key]
    }
  }
  
  return nil
}

func (qb *QB) ColumnsListFromStruct(structIn interface{}, typeTagKey string) (error) {
  var err error
  var structInReflectValue reflect.Value
  var fieldReflectValue reflect.Value
  var field reflect.StructField
  var fieldTag string
  var fieldTypeTag string
  
  if qb == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if structIn == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  structInReflectValue = reflect.ValueOf(structIn)
  
  if !structInReflectValue.IsValid() {
    return errors.New("Struct value is invalid")
  }
  
  if structInReflectValue.Kind() == reflect.Ptr {
    if structInReflectValue.IsNil() {
      return errors.New("Struct pointer is nil")
    }
    
    structInReflectValue = structInReflectValue.Elem()
    
    if !structInReflectValue.IsValid() {
      return errors.New("Struct value is invalid")
    }
  }
  
  if structInReflectValue.Kind() != reflect.Struct {
    return errors.New("Input variable was not Struct")
  }
  
  if typeTagKey == "" {
    return errors.New("SQL type tag value was empty")
  }
  
  for index := 0; index < structInReflectValue.NumField(); index++ {
    fieldReflectValue = structInReflectValue.Field(index)
    field = structInReflectValue.Type().Field(index)
    
    if fieldReflectValue.Kind() == reflect.Struct {
      qb.callLevel++
      err = qb.ColumnsListFromStruct(fieldReflectValue.Interface(), typeTagKey)
      qb.callLevel--
      if err != nil {
        return err
      }
    }
    
    fieldTag = field.Tag.Get(qb.tagKey)
    fieldTypeTag = field.Tag.Get(typeTagKey)
    
    if fieldTag != "" && fieldTypeTag != "" {
      qb.argsCount++
      
      if qb.beginStagePassed == false {
        qb.Query += " ("
        qb.QueryX += " ("
        qb.beginStagePassed = true
      } else {
        qb.Query += ", "
        qb.QueryX += ", "
      }
      
      qb.Query += fieldTag + " " + fieldTypeTag
      qb.QueryX += fieldTag + " " + fieldTypeTag
    }
  }
  
  if qb.callLevel == 0 && qb.argsCount > 0 {
    qb.Query += ")"
    qb.QueryX += ")"
    qb.Query = qb.baseQuery + qb.Query
    qb.QueryX = qb.baseQuery + qb.QueryX
  }
  
  return nil
}

func (qb *QB) SelectListFromStruct(structIn interface{}, selectEmpty bool) (error) {
  var err error
  var structInReflectValue reflect.Value
  var fieldReflectValue reflect.Value
  var field reflect.StructField
  var fieldIsFull bool
  var fieldTag string
  
  if qb == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  if structIn == nil {
    return errors.New("Struct pointer can't be nil")
  }
  
  structInReflectValue = reflect.ValueOf(structIn)
  
  if !structInReflectValue.IsValid() {
    return errors.New("Struct value is invalid")
  }
  
  if structInReflectValue.Kind() == reflect.Ptr {
    if structInReflectValue.IsNil() {
      return errors.New("Struct pointer is nil")
    }
    
    structInReflectValue = structInReflectValue.Elem()
    
    if !structInReflectValue.IsValid() {
      return errors.New("Struct value is invalid")
    }
  }
  
  if structInReflectValue.Kind() != reflect.Struct {
    return errors.New("Input variable was not Struct")
  }
  
  for index := 0; index < structInReflectValue.NumField(); index++ {
    fieldReflectValue = structInReflectValue.Field(index)
    field = structInReflectValue.Type().Field(index)
    
    switch fieldReflectValue.Kind() {
      case reflect.Struct: {
        qb.callLevel++
        err = qb.SelectListFromStruct(fieldReflectValue.Interface(), selectEmpty)
        qb.callLevel--
        if err != nil {
          return err
        }
      }
      
      case reflect.Array, reflect.Map, reflect.Slice, reflect.String: {
        if fieldReflectValue.Len() > 0 {
          fieldIsFull = true
        } else {
          fieldIsFull = false
        }
      }
      
      default: {
        fieldIsFull = false
      }
    }
    
    if selectEmpty {
      fieldIsFull = true
    }
    
    fieldTag = field.Tag.Get(qb.tagKey)
    
    if fieldIsFull && fieldTag != "" {
      qb.argsCount++
      
      if qb.beginStagePassed == false {
        qb.Query += " "
        qb.QueryX += " "
        qb.beginStagePassed = true
      } else {
        qb.Query += ", "
        qb.QueryX += ", "
      }
      
      qb.Query += fieldTag
      qb.QueryX += fieldTag
    }
  }
  
  if qb.callLevel == 0 {
    if qb.argsCount > 0 {
      qb.Query = qb.baseQuery + qb.Query
      qb.QueryX = qb.baseQuery + qb.QueryX
    } else {
      qb.Query = qb.baseQuery + " *"
      qb.QueryX = qb.baseQuery + " *"
    }
  }
  
  return nil
}
