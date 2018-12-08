package checker

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// LookupTXT = net.LookupTXT

func filterByPrefix(records []string, prefix string) []string {
	filtered := []string{}
	for _, elem := range records {
		if elem[0:len(prefix)] == prefix {
			filtered = append(filtered, elem)
		}
	}
	return filtered
}

func parseTXT(record string) map[string]string {
	parsed := make(map[string]string)
	for _, line := range strings.Split(record, ";") {
		split := strings.Split(strings.TrimSpace(line), "=")
		if len(split) != 2 {
			continue
		}
		parsed[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
	}
	return parsed
}

func checkMTASTSRecord(records []string) CheckResult {
	result := CheckResult{Name: "mta-sts-txt"}

	records = filterByPrefix(records, "v=STSv1")
	if len(records) != 1 {
		return result.Failure("exactly 1 MTA-STS TXT record required, found %d", len(records))
	}
	record := parseTXT(records[0])

	id_re := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !id_re.MatchString(record["id"]) {
		return result.Failure("invalid id %s", record["id"])
	}
	return result.Success()
}

// func checkTLSRPTRecord(records []string) error {
// 	records = filterByPrefix(records, "v=STSv1")
// 	if len(records) != 1 {
// 		return fmt.Errorf("exactly 1 TLSRPT TXT record required, found %d", len(records))
// 	}
// 	record := parseTXT(records[0])
// 	if record["v"] != "TLSRPTv1" {
// 		return fmt.Errorf("TLSRPT TXT record version must be TLSRPTv1")
// 	}
// 	// @TODO validate record["rua"]
// 	return nil
// }
//

func checkMTASTS(domain string) ResultGroup {
	result := ResultGroup{
		Status: Success,
		Checks: make(map[string]CheckResult),
	}
	results, err := net.LookupTXT(fmt.Sprintf("_mta-sts.%s", domain))
	if err != nil {
		// @TODO return an failure, probably want to roll into check
		return result
	}
	result.addCheck(checkMTASTSRecord(results))
	return result
}
