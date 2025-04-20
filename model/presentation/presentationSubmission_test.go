package presentation

import "testing"

func TestSubmission(t *testing.T) {
	desc := Description{
		Id:         "bankX",
		FormatType: "ldp_vc",
	}
	sub := CreateSubmission("123", []Description{desc})

	if sub.DefinitionId != "123" || sub.DescriptorMap[0].Id != "bankX" {
		t.Error()
	}
}
