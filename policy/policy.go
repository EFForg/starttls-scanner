package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

// PolicyURL is the default URL from which to fetch the policy JSON.
const PolicyURL = "https://dl.eff.org/starttls-everywhere/policy.json"

// Pinset represents a set of valid public keys for a domain's
// SSL certificate.
type Pinset struct {
	StaticSPKIHashes []string `json:"static-spki-hashes"`
}

// TLSPolicy dictates the policy for a particular email domain.
type TLSPolicy struct {
	PolicyAlias   string   `json:"policy-alias,omitempty"`
	MinTLSVersion string   `json:"min-tls-version,omitempty"`
	Mode          string   `json:"mode"`
	MXs           []string `json:"mxs"`
	Pin           string   `json:"pin,omitempty"`
	Report        string   `json:"report,omitempty"`
}

// List is a raw representation of the policy list.
type list struct {
	Timestamp     time.Time            `json:"timestamp"`
	Expires       time.Time            `json:"expires"`
	Version       string               `json:"version"`
	Author        string               `json:"author"`
	Pinsets       map[string]Pinset    `json:"pinsets"`
	PolicyAliases map[string]TLSPolicy `json:"policy-aliases"`
	Policies      map[string]TLSPolicy `json:"policies"`
}

// Get retrieves the TLSPolicy for a domain, and resolves
// aliases if they exist.
func (l list) get(domain string) (TLSPolicy, error) {
	policy, ok := l.Policies[domain]
	if !ok {
		return TLSPolicy{}, fmt.Errorf("Policy for %d doesn't exist")
	}
	if len(policy.PolicyAlias) > 0 {
		policy, ok = l.PolicyAliases[policy.PolicyAlias]
		if !ok {
			return TLSPolicy{}, fmt.Errorf("Policy alias for %d doesn't exist")
		}
	}
	return policy, nil
}

// UpdatedList wraps a List that is updated from a remote
// policyURL every hour. Safe for concurrent calls to `Get`.
type UpdatedList struct {
	mu sync.RWMutex
	list
}

func (l UpdatedList) Get(domain string) (TLSPolicy, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.list.get(domain)
}

// type listFetcher func(string)

// Retrieve and parse List from policyURL.
func (l UpdatedList) FetchListHTTP(policyURL string) {
	resp, err := http.Get(policyURL)
	if err != nil {
		// Log the error
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var policyList list
	err = json.Unmarshal(body, &policyList)
	if err != nil {
		// Log the error
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = policyList
}

// MakeUpdatedList constructs an UpdatedList object and launches a
// worker thread to continually update it.
func MakeUpdatedList() UpdatedList {
	list := UpdatedList{}

	go func() {
		for {
			list.FetchListHTTP(PolicyURL)
			time.Sleep(time.Hour)
		}
	}()
	return list
}
