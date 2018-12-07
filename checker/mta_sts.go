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

func checkMTASTSRecord(records []string) error {
	records = filterByPrefix(records, "v=STSv1")
	if len(records) != 1 {
		return fmt.Errorf("exactly 1 MTA-STS TXT record required, found %d", len(records))
	}
	record := parseTXT(records[0])

	id_re := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !id_re.MatchString(record["id"]) {
		return fmt.Errorf("invalid id %s", record["id"])
	}
	return nil
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

func checkMTASTS(domain string) error {
	results, err := net.LookupTXT(fmt.Sprintf("_mta-sts.%s", domain))
	if err != nil {
		return err
	}
	err = checkMTASTSRecord(results)
	return err
}
