package presentation

import (
	"encoding/json"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestInputDescriptorFiltering(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(testDefinition), &definition)

	if err != nil {
		t.Error()
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = credential
	credentials["55"] = credential2
	credentials["666"] = credential3

	res, err := definition.Filter(credentials)

	if err != nil || res == nil {
		t.Error()
	}

	if len(res[0].Credentials) != 2 {
		t.Error()
	}

}

func TestInputDescriptorFilteringWithSDJwt(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(testDefinitionSdJwt), &definition)

	if err != nil {
		t.Error()
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = sdjwtcredential
	credentials["2333"] = sdjwtcredential2
	credentials["233333"] = sdjwtCredential3

	res, err := definition.Filter(credentials)

	if err != nil || res == nil {
		t.Error()
	}

	if len(res[0].Credentials) != 2 {
		t.Error()
	}
}

func TestInputDescriptorFilteringContraintWithFilter(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(testDefinitionWithConstraintFilter), &definition)

	if err != nil {
		t.Error()
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = credential
	credentials["55"] = credential2
	credentials["666"] = credential3
	credentials["777"] = credential5
	credentials["888"] = credential6

	res, err := definition.Filter(credentials)

	if err != nil || res == nil {
		t.Error()
	}
	if len(res[0].Credentials) != 1 {
		t.Error()
	}

}

func TestInputDescriptorFilteringWithEmptyDefinition(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(testEmptyDefinition), &definition)

	if err != nil {
		t.Error()
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = credential
	credentials["55"] = credential2
	credentials["666"] = credential3

	res, err := definition.Filter(credentials)

	if err != nil || res == nil {
		t.Error()
	}

	if len(res[0].Credentials) != 3 {
		t.Error()
	}

}

func TestMultipleInputs(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(multipleDescriptors), &definition)

	if err != nil {
		t.Error()
		return
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = credential
	credentials["666"] = credential3

	res, err := definition.Filter(credentials)
	logrus.Info(res[0])
	logrus.Info(res[1])
	if res[0].Credentials == nil || res[1].Credentials == nil {
		t.Error()
	}

	if len(res[0].Credentials) != 1 {
		t.Error()
	}

	if len(res[0].Credentials) != 1 {
		t.Error()
	}

	_, ok := res[0].Credentials["123"]

	if !ok {
		t.Error()
	}

	_, ok = res[1].Credentials["666"]

	if !ok {
		t.Error()
	}
}

func TestFields(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(testDefinitionForFields), &definition)

	if err != nil {
		t.Error()
		return
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = credential
	credentials["666"] = credential4

	res, err := definition.Filter(credentials)

	if len(res[0].Credentials) != 1 {
		t.Error()
	}

	_, ok := res[0].Credentials["666"]

	if !ok {
		t.Error()
	}

}

func TestMarshalling(t *testing.T) {
	var definition PresentationDefinition
	err := json.Unmarshal([]byte(testEmptyDefinition), &definition)

	if err != nil {
		t.Error()
	}

	var credentials = make(map[string]interface{}, 0)

	credentials["123"] = credential
	credentials["55"] = credential2
	credentials["666"] = credential3

	res, err := definition.Filter(credentials)

	if err != nil {
		t.Error()
	}

	b, err := json.Marshal(res)

	if err != nil {
		t.Error()
	}

	var j []map[string]map[string]map[string]map[string]interface{}

	err = json.Unmarshal(b, &j)

	if j[0]["credentials"]["123"] == nil {
		t.Error()
	}

}

const sdjwtcredential = `eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vY2xvdWQtd2FsbGV0Lnhmc2MuZGV2IzAifQ.eyJmYW1pbHlfbmFtZSI6InNmIiwiZ2l2ZW5fbmFtZSI6InNmIiwiY25mIjp7Imp3ayI6eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiI3NzgwYjQ2NC0yZjhiLTQ1YWEtODE0Ni01NTJlNTExOWUzZmMiLCJrdHkiOiJPS1AiLCJ4IjoiNW1ydVg4Z2Yxc3JoRVFfSmMxQi1XamRYN19OUmdwYTBDb1VKWWw5M0diWSJ9fSwiaXNzIjoiaHR0cHM6Ly9jbG91ZC13YWxsZXQueGZzYy5kZXYiLCJpYXQiOjE3MjkxNTg5OTAsInZjdCI6IlNESldUQ3JlZGVudGlhbCIsIl9zZF9hbGciOiJTSEEtMjU2In0.jTdI9bou58IQFo6tNoCcO2wFp9tqWY60eBhkh4d7yK5ye2jN3CHBkaJvlYJ-7Uv9xpmA1RGVbddzrWyPwFX9Bw~`

const sdjwtcredential2 = `eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiLXhWajVmRXN5b1RUSTVURVRrWkY2WUlPdFhUbWtBRnJ4MUs5SmpFc2M1YyIsIlU1MmJMWmtOcnRiTnZNZE9xaF8zRmtvOFlRWGtCZ3ZWNnBXZzh0b29sczgiLCJhM0pwUV9YSEVzMkJKdUFBN0t3UnV4dzN0UGRUOVRDbGp3bDd4Xzk1VENnIl0sIl9zZF9hbGciOiJTSEEtMjU2In0.jBnzvu61kMpxK-nO37fiFWv3oneMRvg-7AJSKWmss7TEzoSEaenLe16crkOPO7dAVyaerzsxRahuadymGOdjhw~WyI4MWY3NDg4YmRiZTJkMjdiIiwiZmlyc3RuYW1lIiwiSm9obiJd~WyIyNDBmNTk4Njc5Mjk2MTU1IiwibGFzdG5hbWUiLCJEb2UiXQ~WyI5MGIzY2Y0NTI2ZDNiZmM4Iiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ`

const sdjwtCredential3 = `eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJmaXJzdG5hbWUiOiJKb2huIiwibGFzdG5hbWUiOiJEb2UiLCJzc24iOiIxMjMtNDUtNjc4OSIsImlkIjoiMTIzNCJ9.61wPJl3vlRbfr6SqeHYpvpJ_ZJI6_XM3YWGfvjSEmKe5dmTfJl7qPaYJ6JdZQKxX3GnZBaxTJcFGq_303w4-ew~`

const credential = `{
	"@context":[],
	"credentialSubject":{
		"dob":"12222"
	},
	"proof": {
	}
}`

const credential2 = `{
	"credentialSubject":{
		"xyz":"12222"
	}
}`

const credential3 = `{
	"credentialSubject":{
		"dateOfBirth":"12222"
	}
}`

const credential4 = `{
	"credentialSubject":{
		"dateOfBirth":"12222",
		"xyz":"111"
	}
}`

const credential5 = `{
	"credentialSubject":{
		"dateOfBirth":"12222",
		"name":"joe"
	}
}`

const credential6 = `{
	"credentialSubjectInvalid":{
		"dateOfBirth":"12222",
		"name":"joe"
	}
}`

const testDefinition = `{
	  "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
	  "input_descriptors": [
		{
		  "id": "wa_driver_license",
		  "name": "Washington State Business License",
		  "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
		  "constraints": {
			"fields": [
			  {
				"path": [
				  "$.credentialSubject.dateOfBirth",
				  "$.credentialSubject.dob",
				  "$.vc.credentialSubject.dateOfBirth",
				  "$.vc.credentialSubject.dob"
				]
			  }
			]
		  }
		}
	  ]
  }`

const testDefinitionSdJwt = `{
	"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
	"input_descriptors": [
	  {
		"id": "wa_driver_license",
		"name": "Washington State Business License",
		"purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
		"constraints": {
		  "fields": [
			{
			  "path": [
				"$.firstname"
			  ]
			}
		  ]
		}
	  }
	]
}`

const testDefinitionWithConstraintFilter = `{
	  "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
	  "input_descriptors": [
		{
		  "id": "wa_driver_license",
		  "name": "Washington State Business License",
		  "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
		  "constraints": {
			"fields": [
			  {
				"path": [
				  "$.credentialSubject",
				  "$.vc.credentialSubject"
				],
				"filter":{
					"type":"string",
					"pattern":"[?(@ =~ /jo/)]"
				}
			  }
			]
		  }
		}
	  ]
  }`

const testDefinitionForFields = `{
	"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
	"input_descriptors": [
	  {
		"id": "wa_driver_license",
		"name": "Washington State Business License",
		"purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
		"constraints": {
		  "fields": [
			{
			  "path": [
				"$.credentialSubject.dateOfBirth"
			  ]
			},
			{
				"path": [
				  "$.credentialSubject.xyz"
				]
			}
		  ]
		}
	  }
	]
}`

const multipleDescriptors = `{
	"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
	"input_descriptors": [
	  {
		"id": "wa_driver_license",
		"name": "Washington State Business License",
		"purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
		"constraints": {
		  "fields": [
			{
			  "path": [
				"$.credentialSubject.dob"
			  ]
			}
		  ]
		}},
		{
			"id": "personalid",
			"name": "Washington State ID card",
			"constraints": {
			  "fields": [
				{
				  "path": [
					"$.credentialSubject.dateOfBirth"
				  ]
				}
			  ]
			}
	  }
	]
}`

const testEmptyDefinition = `{
	"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
	"input_descriptors": []
}`
