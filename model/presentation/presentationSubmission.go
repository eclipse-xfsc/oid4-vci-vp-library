package presentation

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
)

type PresentationSubmission struct {
	Id            string       `json:"id"`
	DefinitionId  string       `json:"definition_id"`
	DescriptorMap []Descriptor `json:"descriptor_map"`
}

type Descriptor struct {
	Id         string     `json:"id"`
	Format     string     `json:"format"`
	Path       string     `json:"path"`
	PathNested PathNested `json:"path_nested,omitempty"`
}

type PathNested struct {
	Format string `json:"format"`
	Path   string `json:"path"`
}

func (submission *PresentationSubmission) CheckSubmissionData() error {

	// make sure mandatory fields are set
	if submission.Id == "" {
		return errors.New("submissionData is missing mandatory field id")
	}

	if submission.DefinitionId == "" {
		return errors.New("submissionData is missing mandatory field definition_id")
	}

	if submission.DescriptorMap == nil || len(submission.DescriptorMap) == 0 {
		return errors.New("descriptormap is missing elements")
	}

	return nil
}

func CreateSubmission(definitionId string, selection []Description) PresentationSubmission {
	submission := PresentationSubmission{
		Id:            uuid.NewString(),
		DefinitionId:  definitionId,
		DescriptorMap: make([]Descriptor, 0),
	}

	c := 0
	for _, d := range selection {
		desc := Descriptor{
			Id:     d.Id,
			Path:   fmt.Sprintf("$.verifiableCredential[%s]", strconv.Itoa(c)),
			Format: d.FormatType,
		}

		submission.DescriptorMap = append(submission.DescriptorMap, desc)

		c++
	}

	return submission
}
