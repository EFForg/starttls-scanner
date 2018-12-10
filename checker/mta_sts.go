package checker

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type MTASTSResult struct {
	Mode        string
	MXHostnames []string
	ResultGroup
}

func filterByPrefix(records []string, prefix string) []string {
	filtered := []string{}
	for _, elem := range records {
		if elem[0:len(prefix)] == prefix {
			filtered = append(filtered, elem)
		}
	}
	return filtered
}

func getKeyValuePairs(record string, lineDelimiter string,
	pairDelimiter string) map[string]string {
	parsed := make(map[string]string)
	for _, line := range strings.Split(record, lineDelimiter) {
		split := strings.Split(strings.TrimSpace(line), pairDelimiter)
		if len(split) != 2 {
			continue
		}
		key := strings.TrimSpace(split[0])
		value := strings.TrimSpace(split[1])
		if parsed[key] == "" {
			parsed[key] = value
		} else {
			parsed[key] = parsed[key] + " " + value
		}
	}
	return parsed
}

func checkMTASTSRecord(domain string) CheckResult {
	result := CheckResult{Name: "mta-sts-txt"}
	records, err := net.LookupTXT(fmt.Sprintf("_mta-sts.%s", domain))
	if err != nil {
		return result.Failure("Couldn't find MTA-STS TXT record: %v", err)
	}
	return validateMTASTSRecord(records, result)
}

func validateMTASTSRecord(records []string, result CheckResult) CheckResult {
	records = filterByPrefix(records, "v=STSv1")
	if len(records) != 1 {
		return result.Failure("exactly 1 MTA-STS TXT record required, found %d", len(records))
	}
	record := getKeyValuePairs(records[0], ";", "=")

	id_re := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !id_re.MatchString(record["id"]) {
		return result.Failure("invalid id %s", record["id"])
	}
	return result.Success()
}

func checkMTASTSPolicyFile(domain string) CheckResult {
	result := CheckResult{Name: "policy_file"}
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	resp, err := http.Get(policyURL)
	// @TODO verify https? verify cert?
	// @TODO don't follow redirect
	// @TODO validate media type is 'text/plain'
	if err != nil {
		return result.Failure("Couldn't find policy file: %v", err)
	}
	if resp.StatusCode != 200 {
		return result.Failure("Couldn't get policy file: %s", resp.Status)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result.Error("Couldn't read policy file: %v", err)
	}

	return validateMTASTSPolicyFile(string(body), result)
}

func validateMTASTSPolicyFile(body string, result CheckResult) CheckResult {
	policy := getKeyValuePairs(body, "\n", ":")

	// Validate version
	if policy["version"] != "STSv1" {
		return result.Error("Policy version must be STSv1")
	}

	// Validate mode
	// @TODO store the mode
	if policy["mode"] == "" {
		return result.Error("Policy file must specify mode")
	}
	if m := policy["mode"]; m != "enforce" && m != "testing" && m != "none" {
		return result.Error("Mode must be one of 'enforce', 'testing', or 'none', got %s", m)
	}

	// Validate max age
	if policy["max_age"] == "" {
		return result.Error("Policy file must specify max_age")
	}
	if i, err := strconv.Atoi(policy["max_age"]); err != nil || i <= 0 || i > 31557600 {
		return result.Error("max_age must be a positive integer <= 31557600")
	}

	// @TODO test with no mxs
	// @TODO store the mxs
	strings.Split(policy["mx"], " ")

	return result.Success()
}

func checkMTASTS(domain string) ResultGroup {
	result := ResultGroup{
		Status: Success,
		Checks: make(map[string]CheckResult),
	}
	result.addCheck(checkMTASTSRecord(domain))
	result.addCheck(checkMTASTSPolicyFile(domain))
	// @TODO add a check to compare hostnames to those supplied by DNS
	return result
}
