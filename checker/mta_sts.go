package checker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// MTASTSResult represents the result of a check for inbound MTA-STS support.
type MTASTSResult struct {
	*Result
	Policy string `json:"policy"` // Text of MTA-STS policy file
	Mode   string `json:"mode"`
}

// MakeMTASTSResult constructs a base result object and returns its pointer.
func MakeMTASTSResult() *MTASTSResult {
	return &MTASTSResult{
		Result: MakeResult(MTASTS),
	}
}

// MarshalJSON prevents MTASTSResult from inheriting the version of MarshalJSON
// implemented by Result.
func (m MTASTSResult) MarshalJSON() ([]byte, error) {
	// type FakeMTASTSResult MTASTSResult
	type FakeResult Result
	return json.Marshal(struct {
		FakeResult
		Policy string `json:"policy"`
		Mode   string `json:"mode"`
	}{
		FakeResult: FakeResult(*m.Result),
		Policy:     m.Policy,
		Mode:       m.Mode,
	})
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

func checkMTASTSRecord(domain string) *Result {
	result := MakeResult(MTASTSText)
	records, err := net.LookupTXT(fmt.Sprintf("_mta-sts.%s", domain))
	if err != nil {
		return result.Failure("Couldn't find an MTA-STS TXT record: %v", err)
	}
	return validateMTASTSRecord(records, result)
}

func validateMTASTSRecord(records []string, result *Result) *Result {
	records = filterByPrefix(records, "v=STSv1")
	if len(records) != 1 {
		return result.Failure("Exactly 1 MTA-STS TXT record required, found %d", len(records))
	}
	record := getKeyValuePairs(records[0], ";", "=")

	idPattern := regexp.MustCompile("^[a-zA-Z0-9]+$")
	if !idPattern.MatchString(record["id"]) {
		return result.Failure("Invalid id %s", record["id"])
	}
	return result.Success()
}

func checkMTASTSPolicyFile(domain string, hostnameResults map[string]HostnameResult) (*Result, string, string) {
	result := MakeResult(MTASTSPolicyFile)
	client := &http.Client{
		// Don't follow redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	resp, err := client.Get(policyURL)
	if err != nil {
		return result.Failure("Couldn't find policy file at %s", policyURL), "", ""
	}
	if resp.StatusCode != 200 {
		return result.Failure("Couldn't get policy file: %s returned %s", policyURL, resp.Status), "", ""
	}
	// Media type should be text/plain, ignoring other Content-Type parms.
	// Format: Content-Type := type "/" subtype *[";" parameter]
	for _, contentType := range resp.Header["Content-Type"] {
		contentType := strings.ToLower(contentType)
		if strings.HasPrefix(contentType, "text/plain") {
			return result.Warning("Media type must be text/plain"), "", ""
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result.Error("Couldn't read policy file: %v", err), "", ""
	}

	policy := validateMTASTSPolicyFile(string(body), result)
	validateMTASTSMXs(strings.Split(policy["mx"], " "), hostnameResults, result)
	return result, string(body), policy["mode"]
}

func validateMTASTSPolicyFile(body string, result *Result) map[string]string {
	policy := getKeyValuePairs(body, "\n", ":")

	if policy["version"] != "STSv1" {
		result.Failure("Policy version must be STSv1")
	}

	if policy["mode"] == "" {
		result.Failure("Policy file must specify mode")
	}
	if m := policy["mode"]; m != "enforce" && m != "testing" && m != "none" {
		result.Failure("Mode must be one of 'enforce', 'testing', or 'none', got %s", m)
	}

	if policy["max_age"] == "" {
		result.Failure("Policy file must specify max_age")
	}
	if i, err := strconv.Atoi(policy["max_age"]); err != nil || i <= 0 || i > 31557600 {
		result.Failure("max_age must be a positive integer <= 31557600")
	}

	return policy
}

func validateMTASTSMXs(policyFileMXs []string, dnsMXs map[string]HostnameResult,
	result *Result) {
	for dnsMX, dnsMXResult := range dnsMXs {
		if !dnsMXResult.couldConnect() {
			// Ignore hostnames we couldn't connect to, they may be spam traps.
			continue
		}
		if !policyMatches(dnsMX, policyFileMXs) {
			result.Warning("%s appears in the DNS record but not the MTA-STS policy file",
				dnsMX)
		} else if !dnsMXResult.couldSTARTTLS() {
			result.Warning("%s appears in the DNS record and MTA-STS policy file, but doesn't support STARTTLS",
				dnsMX)
		}
	}
}

func (c Checker) checkMTASTS(domain string, hostnameResults map[string]HostnameResult) *MTASTSResult {
	result := MakeMTASTSResult()
	result.addCheck(checkMTASTSRecord(domain))
	policyResult, policy, mode := checkMTASTSPolicyFile(domain, hostnameResults)
	result.addCheck(policyResult)
	result.Policy = policy
	result.Mode = mode
	return result
}
