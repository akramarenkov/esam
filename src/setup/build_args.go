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
  "errors"
  "reflect"
)

const (
  optTag = "opt"
  manyValuesDelimiter = ","
)

func buildArgs(structIn interface{}) ([]string, error) {
  var structInRV reflect.Value
  var args []string
  
  structInRV = reflect.ValueOf(structIn)
  
  if !structInRV.IsValid() {
    return nil, errors.New("Input variable is invalid")
  }
  
  if structInRV.Kind() != reflect.Struct {
    return nil, errors.New("Input variable is not struct")
  }
  
  args = make([]string, 0)
  
  for index := 0; index < structInRV.NumField(); index++ {
    var fieldRV reflect.Value
    var field reflect.StructField
    var fieldOpt string
    var fieldValue string
    
    fieldRV = structInRV.Field(index)
    field = structInRV.Type().Field(index)
    
    fieldOpt = field.Tag.Get(optTag)
    
    switch fieldRV.Kind() {
      case reflect.String: {
        fieldValue = fieldRV.String()
        
        if fieldOpt != "" && fieldValue != "" {
          if fieldValue == " " {
            fieldValue = ""
          }
          
          args = append(args, fieldOpt)
          args = append(args, fieldValue)
        }
      }
      
      case reflect.Array, reflect.Slice: {
        if fieldRV.Len() > 0 {
          switch fieldRV.Type().Elem().Kind() {
            case reflect.String: {
              if fieldRV.Len() == 1 && fieldRV.Index(0).String() == " " {
                if fieldOpt != "" {
                  args = append(args, fieldOpt)
                  args = append(args, "")
                }
              } else {
                for jndex := 0; jndex < fieldRV.Len(); jndex++ {
                  var fieldSubValue string
                  
                  fieldSubValue = fieldRV.Index(jndex).String()
                  
                  if fieldSubValue != "" {
                    if fieldValue == "" {
                      fieldValue = fieldSubValue
                    } else {
                      fieldValue = fieldValue + manyValuesDelimiter + fieldSubValue
                    }
                  }
                }
                
                if fieldOpt != "" && fieldValue != "" {
                  args = append(args, fieldOpt)
                  args = append(args, fieldValue)
                }
              }
            }
            
            default: {
              return nil, errors.New("Unsupported field type")
            }
          }
        }
      }
      
      case reflect.Bool: {
        if fieldOpt != "" && fieldRV.Bool() {
          args = append(args, fieldOpt)
        }
      }
      
      default: {
        return nil, errors.New("Unsupported field type")
      }
    }
  }
  
  return args, nil
}
