package models

import (
	"fmt"
	"time"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/policy"
)

type PolicySubmission struct {
	Domain       string
	ContactEmail string
	MTASTS       bool
	Policy       *policy.TLSPolicy
}

type policyStore interface {
	GetPolicies(bool) ([]PolicySubmission, error)
	GetPolicy(string) (PolicySubmission, error)
	RemovePolicy(string) (PolicySubmission, error)
	PutOrUpdatePolicy(*PolicySubmission) error
}

// In some cases, you should be able to replace the existing policy with
// a new one. In some cases, you shouldn't.
// For instance, if the only difference between the policies is the email
// address, then it should be fine.
func (p *PolicySubmission) CanUpdate(policies policyStore) bool {
	oldPolicy, err := policies.GetPolicy(p.Domain)
	if err != nil {
		return true
	}
	// If the policies are the same, return true if emails are different
	if (oldPolicy.MTASTS && p.MTASTS) || oldPolicy.Policy.HostnamesEqual(p.Policy) {
		return oldPolicy.ContactEmail != p.ContactEmail
	}
	// If both policies are in manual mode, we can update the old one if it's still in testing
	if !p.MTASTS && !oldPolicy.MTASTS {
		return oldPolicy.Policy.Mode == "testing"
	}
	return false
}

// Initial validation check. Not meant to be bullet-proof (state can change between
// initial submission and addition to the list), but as a premature failure when
// we can detect it.
func (p *PolicySubmission) HasValidScan(scans scanStore) (bool, string) {
	scan, err := scans.GetLatestScan(p.Domain)
	if err != nil {
		return false, "We haven't scanned this domain yet. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission"
	}
	if scan.Timestamp.Add(time.Minute * 10).Before(time.Now()) {
		return false, "We haven't scanned this domain recently. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission"
	}
	if scan.Data.Status != 0 {
		return false, "Domain hasn't passed our STARTTLS security checks"
	}
	// Domains without submitted MTA-STS support must match provided mx patterns.
	if !p.MTASTS {
		for _, hostname := range scan.Data.PreferredHostnames {
			if !checker.PolicyMatches(hostname, p.Policy.MXs) {
				return false, fmt.Sprintf("Hostnames %v do not match policy %v", scan.Data.PreferredHostnames, p.Policy.MXs)
			}
		}
	} else if !scan.SupportsMTASTS() {
		return false, "Domain does not correctly implement MTA-STS."
	}
	return true, ""
}

func (d *PolicySubmission) InitializeWithToken(pendingPolicies policyStore, tokens tokenStore) (string, error) {
	if err := pendingPolicies.PutOrUpdatePolicy(d); err != nil {
		return "", err
	}
	token, err := tokens.PutToken(d.Domain)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}
