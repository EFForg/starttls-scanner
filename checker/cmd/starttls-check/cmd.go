package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

// Expects domains to be delimited by newlines.
func domainsFromFile(filename string) ([]string, error) {
	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	allContent := string(buff)
	// Filter empty lines from domain list
	filterDomains := make([]string, 0)
	for _, line := range strings.Split(allContent, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		filterDomains = append(filterDomains, trimmed)
	}
	return filterDomains, nil
}

// Run a series of security checks on an MTA domain.
// =================================================
// Validating (START)TLS configurations for all MX domains.
//
// CLI arguments
// =============
//     -domain <domain> The domain to perform checks against.
//
func main() {
	// 1. Setup and parse arguments.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nNOTE: All checks are enabled by default. "+
			"Setting any individual 'enable check' flag will disable "+
			"all checks other than the ones explicitly specified.\n\n")
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	domainStr := flag.String("domain", "", "Required: Domain to check TLS for.")
	domainsFileStr := flag.String("domains", "", "Required: Domain to check TLS for.")
	mtasts := flag.Bool("mtasts", false, "Whether to check for MTA-STS advertisement")
	flag.Parse()
	if *domainStr == "" && *domainsFileStr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	var result interface{}
	if *mtasts && *domainsFileStr == "" {
		singleResult := checker.CheckMTASTS(*domainStr)
		fmt.Printf("%s,%t,%t\n",
			singleResult.Domain,
			singleResult.Support,
			singleResult.Testing)
		os.Exit(0)
	} else if *domainStr != "" {
		result = checker.CheckDomain(*domainStr, nil)
	} else if *domainsFileStr != "" {
		var list []interface{}
		domains, _ := domainsFromFile(*domainsFileStr)
		for _, domain := range domains {
			var single interface{}
			if *mtasts {
				singleResult := checker.CheckMTASTS(domain)

				fmt.Printf("%s,%t,%t\n",
					singleResult.Domain,
					singleResult.Support,
					singleResult.Testing)
				single = singleResult
			} else {
				single = checker.CheckDomain(domain, nil)
			}
			list = append(list, single)
			time.Sleep(100 * time.Millisecond)
		}
		result = list
	}
	b, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("%q", err)
	}
	fmt.Println(string(b))
}
