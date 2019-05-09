package models

import (
	"log"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

/* Domain represents an email domain's TLS policy.
 *
 * If there's a Domain object for a particular email domain in "Enforce" mode,
 * that email domain's policy is fixed and cannot be changed.
 */

// Domain stores the preload state of a single domain.
type Domain struct {
	Name         string      `json:"domain"` // Domain that is preloaded
	Email        string      `json:"-"`      // Contact e-mail for Domain
	MXs          []string    `json:"mxs"`    // MXs that are valid for this domain
	MTASTS       bool        `json:"mta_sts"`
	State        DomainState `json:"state"`
	LastUpdated  time.Time   `json:"last_updated"`
	TestingStart time.Time   `json:"-"`
	QueueWeeks   int         `json:"queue_weeks"`
}

// domainStore is a simple interface for fetching and adding domain objects.
type domainStore interface {
	PutDomain(Domain) error
	GetDomain(string, DomainState) (Domain, error)
	GetDomains(DomainState) ([]Domain, error)
	SetStatus(string, DomainState) error
	RemoveDomain(string, DomainState) (Domain, error)
}

// DomainState represents the state of a single domain.
type DomainState string

// Possible values for DomainState
const (
	StateUnknown     = "unknown"     // Domain was never submitted, so we don't know.
	StateUnconfirmed = "unvalidated" // Administrator has not yet confirmed their intention to add the domain.
	StateTesting     = "queued"      // Queued for addition at next addition date pending continued validation
	StateFailed      = "failed"      // Requested to be queued, but failed verification.
	StateEnforce     = "added"       // On the list.
)

type policyList interface {
	HasDomain(string) bool
}

// PolicyListCheck checks the policy list status of this particular domain.
func (d *Domain) PolicyListCheck(store domainStore, list policyList) *checker.Result {
	result := checker.Result{Name: checker.PolicyList}
	if list.HasDomain(d.Name) {
		return result.Success()
	}
	domain, err := GetDomain(store, d.Name)
	if err != nil {
		return result.Failure("Domain %s is not on the policy list.", d.Name)
	}
	if domain.State == StateEnforce {
		log.Println("Warning: Domain was StateEnforce in DB but was not found on the policy list.")
		return result.Success()
	}
	if domain.State == StateTesting {
		return result.Warning("Domain %s is queued to be added to the policy list.", d.Name)
	}
	if domain.State == StateUnconfirmed {
		return result.Failure("The policy addition request for %s is waiting on email validation", d.Name)
	}
	return result.Failure("Domain %s is not on the policy list.", d.Name)
}

// AsyncPolicyListCheck performs PolicyListCheck asynchronously.
// domainStore and policyList should be safe for concurrent use.
func (d Domain) AsyncPolicyListCheck(store domainStore, list policyList) <-chan checker.Result {
	result := make(chan checker.Result)
	go func() { result <- *d.PolicyListCheck(store, list) }()
	return result
}

// GetDomain retrieves Domain with the most "important" state.
// At any given time, there can only be one domain that's either StateEnforce
// or StateTesting. If that domain exists in the store, return that one.
// Otherwise, look for a Domain policy in the unconfirmed state.
func GetDomain(store domainStore, name string) (Domain, error) {
	domain, err := store.GetDomain(name, StateEnforce)
	if err == nil {
		return domain, nil
	}
	domain, err = store.GetDomain(name, StateTesting)
	if err == nil {
		return domain, nil
	}
	domain, err = store.GetDomain(name, StateUnconfirmed)
	if err == nil {
		return domain, nil
	}
	return store.GetDomain(name, StateFailed)
}
