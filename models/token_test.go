package models

import (
	"errors"
	"testing"
)

type mockTokenStore struct {
	token  *Token
	domain string
	err    error
}

func (m *mockTokenStore) PutToken(domain string) (Token, error) {
	m.token = &Token{Domain: domain, Token: "token"}
	return *m.token, m.err
}

func (m *mockTokenStore) UseToken(token string) (string, error) {
	return m.domain, m.err
}

func TestRedeemToken(t *testing.T) {
	pending := mockPolicyStore{policy: PolicySubmission{Name: "anything"}, err: nil}
	store := mockPolicyStore{}
	token := Token{Token: "token"}
	domain, userErr, dbErr := token.Redeem(&pending, &store, &mockTokenStore{domain: "anything", err: nil})
	if domain != "anything" || userErr != nil || dbErr != nil {
		t.Error("Expected token redeem to succeed")
	}
	if store.policy.Name != "anything" && pending.policy.Name != "-removed-" {
		t.Error("Expected PutDomain to have upgraded domain State")
	}
}

func TestRedeemTokenFailures(t *testing.T) {
	token := Token{Token: "token"}
	_, userErr, _ := token.Redeem(&mockPolicyStore{}, &mockPolicyStore{}, &mockTokenStore{err: errors.New("")})
	if userErr == nil {
		t.Error("Errors reported from the token store should be interpreted as usage error (token already used, or doesn't exist)")
	}
	_, _, dbErr := token.Redeem(&mockPolicyStore{}, &mockPolicyStore{err: errors.New("")}, &mockTokenStore{})
	if dbErr == nil {
		t.Error("Errors reported from the domain store should be interpreted as a hard failure")
	}
	_, _, dbErr = token.Redeem(&mockPolicyStore{err: errors.New("")}, &mockPolicyStore{}, &mockTokenStore{})
	if dbErr == nil {
		t.Error("Errors reported from the domain store should be interpreted as a hard failure")
	}
}
