package models

import (
	"errors"
	"strings"
	"testing"

	"github.com/EFForg/starttls-backend/checker"
)

type mockList struct {
	hasDomain bool
}

func (m mockList) HasDomain(string) bool { return m.hasDomain }

type mockScanStore struct {
	scan Scan
	err  error
}

func (m mockScanStore) GetLatestScan(string) (Scan, error) { return m.scan, m.err }

func TestIsQueueable(t *testing.T) {
	// With supplied hostnames
	d := Domain{
		Name:  "example.com",
		Email: "me@example.com",
		MXs:   []string{"mx1.example.com", "mx2.example.com"},
	}
	goodScan := Scan{
		Data: checker.DomainResult{
			PreferredHostnames: []string{"mx1.example.com", "mx2.example.com"},
			MTASTSResult:       checker.MakeMTASTSResult(),
		},
	}
	ok, msg := d.IsQueueable(mockScanStore{goodScan, nil}, mockList{false})
	if !ok {
		t.Error("Unadded domain with passing scan should be queueable, got " + msg)
	}
	ok, msg = d.IsQueueable(mockScanStore{goodScan, nil}, mockList{true})
	if ok || !strings.Contains(msg, "already on the policy list") {
		t.Error("Domain on policy list should not be queueable, got " + msg)
	}
	failedScan := Scan{
		Data: checker.DomainResult{Status: checker.DomainFailure},
	}
	ok, msg = d.IsQueueable(mockScanStore{failedScan, nil}, mockList{false})
	if ok || !strings.Contains(msg, "hasn't passed") {
		t.Error("Domain with failing scan should not be queueable, got " + msg)
	}
	ok, msg = d.IsQueueable(mockScanStore{Scan{}, errors.New("")}, mockList{false})
	if ok || !strings.Contains(msg, "haven't scanned") {
		t.Error("Domain without scan should not be queueable, got " + msg)
	}
	wrongMXsScan := Scan{
		Data: checker.DomainResult{
			PreferredHostnames: []string{"mx1.example.com"},
		},
	}
	ok, msg = d.IsQueueable(mockScanStore{wrongMXsScan, nil}, mockList{false})
	if ok || !strings.Contains(msg, "supplied hostnames") {
		t.Error("Domain with mismatched hostnames should not be queueable, got " + msg)
	}
	// With MTA-STS
	d = Domain{
		Name:       "example.com",
		Email:      "me@example.com",
		MTASTSMode: "on",
	}
	ok, msg = d.IsQueueable(mockScanStore{goodScan, nil}, mockList{false})
	if !ok {
		t.Error("Unadded domain with passing scan should be queueable, got " + msg)
	}
	noMTASTSScan := Scan{
		Data: checker.DomainResult{
			MTASTSResult: &checker.MTASTSResult{
				Result: &checker.Result{
					Status: checker.Failure,
				},
			},
		},
	}
	ok, msg = d.IsQueueable(mockScanStore{noMTASTSScan, nil}, mockList{false})
	if ok || !strings.Contains(msg, "MTA-STS") {
		t.Error("Domain without MTA-STS or hostnames should not be queueable, got " + msg)
	}
}
