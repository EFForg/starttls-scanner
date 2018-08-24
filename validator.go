package main

import (
	"log"
	"time"

	"github.com/EFForg/starttls-check/checker"
	"github.com/EFForg/starttls-scanner/db"
)

func failDomain(database *db.Database, domain string) error {
	return (*database).PutDomain(db.DomainData{
		Name:  domain,
		State: db.StateFailed,
	})
}

func tryFailDomains(database *db.Database, domains []string) {
	for _, domain := range domains {
		err := failDomain(database, domain)
		if err != nil {
			log.Printf("Could not fail domain %s: %s", domain, err.Error())
		}
		SendQueueValidationFailed(domain)
	}
}

func validateQueued(database *db.Database) {
	queued, err := (*database).GetDomains(db.StateQueued)
	if err != nil {
		// TODO: log error. this shouldn't happen!
	}
	failed := []string{}
	for _, domainData := range queued {
		result := checker.CheckDomain(domainData.Name, domainData.MXs)
		if result.Status != 0 {
			failed = append(failed, domainData.Name)
			// TODO: log failure reasons
		}
	}
	tryFailDomains(database, failed)
}

func tryNotifyDomains(database *db.Database, domains []string) {
	for _, domain := range domains {
		SendListValidationFailed(domain)
	}
}

func validateList(list *PolicyList, database *db.Database) {
	failed := []string{}
	domains, err := (*list).GetDomains()
	if err != nil {
		// log error. This shouldn't happen!
	}
	for _, domain := range domains {
		policy, err := (*list).Get(domain)
		if err != nil {
			// log error. This shouldn't happen!
		}
		result := checker.CheckDomain(domain, policy.MXs)
		if result.Status != 0 {
			failed = append(failed, domain)
			// TODO: log failure reasons
		}
	}
	tryNotifyDomains(database, failed)
}

func validator(database *db.Database, list *PolicyList) {
	for {
		<-time.After(time.Hour * 24)
		validateQueued(database)
		validateList(list, database)
	}
}
