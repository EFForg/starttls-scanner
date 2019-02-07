package models

import (
	"time"
)

// Domain stores the preload state of a single domain.
type Domain struct {
	Name        string      `json:"domain"` // Domain that is preloaded
	Email       string      `json:"-"`      // Contact e-mail for Domain
	MXs         []string    `json:"mxs"`    // MXs that are valid for this domain
	MTASTSMode  string      `json:"mta_sts"`
	State       DomainState `json:"state"`
	LastUpdated time.Time   `json:"last_updated"`
}

// DomainState represents the state of a single domain.
type DomainState string

// Possible values for DomainState
const (
	StateUnknown     = "unknown"     // Domain was never submitted, so we don't know.
	StateUnvalidated = "unvalidated" // E-mail token for this domain is unverified
	StateQueued      = "queued"      // Queued for addition at next addition date.
	StateFailed      = "failed"      // Requested to be queued, but failed verification.
	StateAdded       = "added"       // On the list.
)

type policyList interface {
	HasDomain(string) bool
}

type scanStore interface {
	GetLatestScan(string) (Scan, error)
}

// IsQueueable returns true if a domain can be submitted for validation and
// queueing to the STARTTLS Everywhere Policy List.
func (d *Domain) IsQueueable(db scanStore, list policyList) (bool, string) {
	scan, err := db.GetLatestScan(d.Name)
	if err != nil {
		return false, "We haven't scanned this domain yet. " +
			"Please use the STARTTLS checker to scan your domain's " +
			"STARTTLS configuration so we can validate your submission"
	}
	if scan.Data.Status != 0 {
		return false, "Domain hasn't passed our STARTTLS security checks"
	}
	if list.HasDomain(d.Name) {
		return false, "Domain is already on the policy list!"
	}
	if d.MTASTSMode != "" && !scan.SupportsMTASTS() {
		return false, "Domain does not correctly implement MTA-STS."
	} else if !subset(d.MXs, scan.Data.PreferredHostnames) {
		return false, "Domain is not valid for the supplied hostnames."
	}
	return true, ""
}

func subset(small []string, big []string) bool {
	for _, s := range small {
		if !containsString(big, s) {
			return false
		}
	}
	return true
}

func containsString(l []string, s string) bool {
	for _, li := range l {
		if s == li {
			return true
		}
	}
	return false
}
