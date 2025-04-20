// SPDX-FileCopyrightText: 2023 DTIT and TLABS.
// SPDX-License-Identifier: Apache-2.0

// https://identity.foundation/presentation-exchange/#input-descriptor-object
package presentation

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/oliveagle/jsonpath"
)

type ValidPresentation struct {
	Valid              bool                   `json:"valid"`
	Disclosure         map[string]interface{} `json:"disclosure"`
	RequiredDisclosure []string               `json:"required_disclosure"`
}

type Constraints struct {
	LimitDisclosure Disclosure `json:"limit_disclosure,omitempty"` //The constraints object MAY contain a limit_disclosure property
	Fields          []Field    `json:"fields,omitempty"`           //The constraints object MAY contain a fields property
}

type Disclosure string

const (
	Required  Disclosure = "required"
	Preferred Disclosure = "preferred"
)

type InputDescriptor struct {
	Description
	Format      Format      `json:"format"`
	Constraints Constraints `json:"constraints"`
	Group       []string    `json:"group,omitempty"`
}

type PresentationDefinition struct {
	Description
	InputDescriptors       []InputDescriptor       `json:"input_descriptors"`
	Format                 Format                  `json:"format,omitempty"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
}

type Description struct {
	Id         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Purpose    string `json:"purpose,omitempty"`
	FormatType string `json:"format"`
}

type SubmissionRequirement struct {
	Rule    Rule   `json:"rule"`
	From    string `json:"from"`
	Name    string `json:"name,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

type Rule string

const (
	All  Rule = "all"
	Pick Rule = "pick"
)

type Format struct {
	SDJWT *FormatSpecification `json:"verifiable-credential+sd-jwt,omitempty"`
	LDPVP *FormatSpecification `json:"ldp_vp,omitempty"`
	LDP   *FormatSpecification `json:"ldp,omitempty"`
	LDPVC *FormatSpecification `json:"ldp_vc,omitempty"`
	JWT   *FormatSpecification `json:"jwt,omitempty"`
	JWTVC *FormatSpecification `json:"jwt_vc,omitempty"`
	JWTVP *FormatSpecification `json:"jwt_vp,omitempty"`
	//TODO: add others
}

type Field struct {
	Path    []string `json:"path"`              //Mandatory Field
	Id      string   `json:"id,omitempty"`      //Optional Field
	Purpose string   `json:"purpose,omitempty"` //Optional Field
	Filter  *Filter  `json:"filter,omitempty"`  //Optional Field
	Name    string   `json:"name,omitempty"`    //Optional Field
}

type Filter struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type FormatSpecification struct {
	ProofType []ProofType `json:"proof_type,omitempty"`
	Alg       []Alg       `json:"alg,omitempty"`
}

type CredentialResult struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

type FilterResult struct {
	Description `json:"description"`
	Credentials map[string]CredentialResult `json:"credentials"`
}

type Alg string

const (
	EDDSA Alg = "EdDSA"
	ES256 Alg = "ES256"
	PS256 Alg = "PS256"
	//TODO Add More
)

type ProofType string

const (
	JsonWebSignature2020        ProofType = "JsonWebSignature2020"
	Ed25519Signature2018        ProofType = "Ed25519Signature2018"
	EcdsaSecp256k1Signature2019 ProofType = "EcdsaSecp256k1Signature2019"
	RsaSignature2018            ProofType = "RsaSignature2018"
	//TODO Add More
)

func (definition *PresentationDefinition) CheckPresentationDefinition() error {

	if definition.InputDescriptors == nil || len(definition.InputDescriptors) == 0 {
		return errors.New("input descriptor map empty")
	} else {
		for i, x := range definition.InputDescriptors {

			if x.Description.Id == "" {
				return fmt.Errorf("id empty of descriptor %s", strconv.Itoa(i))
			}
		}
	}

	return nil
}

func (definition *PresentationDefinition) Filter(credentials map[string]interface{}) ([]FilterResult, error) {
	var result []FilterResult = make([]FilterResult, 0)
	var temp map[Description]*FilterResult = make(map[Description]*FilterResult)

	for i, c := range credentials {
		credential, err := types.CheckFormat(c)

		if err != nil || credential == nil || credential.Format == types.UNKNOWN {
			return nil, errors.New("credential format not supported.")
		}

		if len(definition.InputDescriptors) > 0 {
			for _, d := range definition.InputDescriptors {
				b, err := d.Filter(credential)

				if err != nil {
					return nil, errors.New("descriptor cant be evaluated.")
				}

				if b {
					d.Description.FormatType = string(credential.Format)
					if temp[d.Description] == nil {
						temp[d.Description] = &FilterResult{
							Credentials: make(map[string]CredentialResult),
							Description: d.Description,
						}

					}
					temp[d.Description].Credentials[i] = CredentialResult{
						Type: string(credential.Format),
						Data: c,
					}
				}
			}
		} else {
			if temp[definition.Description] == nil {
				temp[definition.Description] = &FilterResult{
					Credentials: make(map[string]CredentialResult),
					Description: definition.Description,
				}
			}

			temp[definition.Description].Credentials[i] = CredentialResult{
				Type: string(credential.Format),
				Data: c,
			}
			//TODO Format Filtering when Inputdescriptors are not available?
		}
	}

	for _, d := range temp {
		result = append(result, *d)
	}

	return result, nil
}

func (format *Format) CheckFormats() error {
	formats := []*FormatSpecification{
		format.SDJWT,
		format.LDPVP,
		format.LDP,
		format.JWT,
		format.JWTVC,
		format.JWTVP}

	var allEmpty = true
	for _, f := range formats {
		allEmpty = allEmpty && f == nil

		if f != nil {
			if f == format.LDPVC || f == format.LDP || f == format.LDPVP {
				if f == format.LDPVC {
					if format.LDPVC.ProofType == nil {
						return errors.New("proof_type missing")
					}
				}
				if f == format.LDPVP {
					if format.LDPVP.ProofType == nil {
						return errors.New("proof_type missing")
					}
				}
				if f == format.LDP {
					if format.LDP.ProofType == nil {
						return errors.New("proof_type missing")
					}
				}
				//TODO Add more format checks
			}
		}
	}

	if allEmpty {
		return errors.New("input descriptor formats is empty")
	}
	return nil
}

func (descriptor *InputDescriptor) Filter(credential *types.Credential) (bool, error) {
	var descriptorfullFilled = false
	for _, c := range descriptor.Constraints.Fields {
		var match = false

		for _, p := range c.Path {
			res, err := jsonpath.JsonPathLookup(credential.Json, p)
			if err != nil {
				continue
			}
			match = descriptor.ApplyFieldFilter(res, c)
		}
		descriptorfullFilled = descriptorfullFilled || match
	}
	return descriptorfullFilled, nil
}

func (descriptor *InputDescriptor) ApplyFieldFilter(value interface{}, filter Field) bool {
	if value != nil {
		switch value.(type) {
		case string:
			return descriptor.matchPattern(value.(string), filter)

		case map[string]interface{}:
			for _, v := range value.(map[string]interface{}) {
				if descriptor.ApplyFieldFilter(v, filter) {
					return true
				}
			}
			return false

		default:
			return false
		}
	}
	return false
}

func (descriptor *InputDescriptor) matchPattern(res string, c Field) bool {
	if c.Filter != nil {
		if c.Filter.Type != "" {
			//	todo implement type filter
		}
		if p := c.Filter.Pattern; p != "" {
			regex := regexp.MustCompile(c.Filter.Pattern)
			return regex.MatchString(res)
		}
	}
	return true
}
