package main

import (
	"testing"

	"github.com/EFForg/starttls-check/checker"
)

func TestPolicyCheck(t *testing.T) {
	defer Teardown()

	result := api.policyCheck("eff.org")
	if result.Status != checker.Success {
		t.Errorf("Check should have succeeded.")
	}
	result = api.policyCheck("failmail.com")
	if result.Status != checker.Failure {
		t.Errorf("Check should have failed.")
	}
}
