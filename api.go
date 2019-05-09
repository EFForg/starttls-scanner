package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/EFForg/starttls-backend/checker"
	"github.com/EFForg/starttls-backend/db"
	"github.com/EFForg/starttls-backend/models"
	"github.com/EFForg/starttls-backend/policy"
	"github.com/getsentry/raven-go"
)

////////////////////////////////
//  *****   REST API   *****  //
////////////////////////////////

// Minimum time to cache each domain scan
const cacheScanTime = time.Minute

// Type for performing checks against an input domain. Returns
// a DomainResult object from the checker.
type checkPerformer func(API, string) (checker.DomainResult, error)

// API is the HTTP API that this service provides.
// All requests respond with an APIResponse JSON, with fields:
// {
//     status_code // HTTP status code of request
//     message // Any error message accompanying the status_code. If 200, empty.
//     response // Response data (as JSON) from this request.
// }
// Any POST request accepts either URL query parameters or data value parameters,
// and prefers the latter if both are present.
type API struct {
	Database    *db.SQLDatabase
	CheckDomain checkPerformer
	List        PolicyList
	DontScan    map[string]bool
	Emailer     EmailSender
	Templates   map[string]*template.Template
}

// PolicyList interface wraps a policy-list like structure.
// The most important query you can perform is to fetch the policy
// for a particular domain.
type PolicyList interface {
	HasDomain(string) bool
	Raw() policy.List
}

// EmailSender interface wraps a back-end that can send e-mails.
type EmailSender interface {
	// SendValidation sends a validation e-mail for a particular domain,
	// with a particular validation token.
	SendValidation(*models.PolicySubmission, string) error
}

// APIResponse wraps all the responses from this API.
type APIResponse struct {
	StatusCode   int         `json:"status_code"`
	Message      string      `json:"message"`
	Response     interface{} `json:"response"`
	templateName string      `json:"-"`
}

type apiHandler func(r *http.Request) APIResponse

func (api *API) wrapper(handler apiHandler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		response := handler(r)
		if response.StatusCode == http.StatusInternalServerError {
			packet := raven.NewPacket(response.Message, raven.NewHttp(r))
			raven.Capture(packet, nil)
		}
		if strings.Contains(r.Header.Get("accept"), "text/html") {
			api.writeHTML(w, response)
		} else {
			api.writeJSON(w, response)
		}
	}
}

func defaultCheck(api API, domain string) (checker.DomainResult, error) {
	policyChan := models.Domain{Name: domain}.AsyncPolicyListCheck(api.Database, api.List)
	c := checker.Checker{
		Cache: &checker.ScanCache{
			ScanStore:  api.Database,
			ExpireTime: 5 * time.Minute,
		},
		Timeout: 3 * time.Second,
	}
	result := c.CheckDomain(domain, nil)
	policyResult := <-policyChan
	result.ExtraResults["policylist"] = &policyResult
	return result, nil
}

// Scan is the handler for /api/scan.
//   POST /api/scan
//        domain: Mail domain to scan.
//        Scans domain and returns data from it.
//   GET /api/scan?domain=<domain>
//        Retrieves most recent scan for domain.
// Both set a models.Scan JSON as the response.
func (api API) Scan(r *http.Request) APIResponse {
	domain, err := getASCIIDomain(r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	// Check if we shouldn't scan this domain
	if api.DontScan != nil {
		if _, ok := api.DontScan[domain]; ok {
			return APIResponse{StatusCode: http.StatusTooManyRequests}
		}
	}
	// POST: Force scan to be conducted
	if r.Method == http.MethodPost {
		// 0. If last scan was recent and on same scan version, return cached scan.
		scan, err := api.Database.GetLatestScan(domain)
		if err == nil && scan.Version == models.ScanVersion &&
			time.Now().Before(scan.Timestamp.Add(cacheScanTime)) {
			return APIResponse{
				StatusCode:   http.StatusOK,
				Response:     scan,
				templateName: "scan",
			}
		}
		// 1. Conduct scan via starttls-checker
		scanData, err := api.CheckDomain(api, domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		scan = models.Scan{
			Domain:    domain,
			Data:      scanData,
			Timestamp: time.Now(),
			Version:   models.ScanVersion,
		}
		// 2. Put scan into DB
		err = api.Database.PutScan(scan)
		if err != nil {
			return APIResponse{StatusCode: http.StatusInternalServerError, Message: err.Error()}
		}
		return APIResponse{
			StatusCode:   http.StatusOK,
			Response:     scan,
			templateName: "scan",
		}
		// GET: Just fetch the most recent scan
	} else if r.Method == http.MethodGet {
		scan, err := api.Database.GetLatestScan(domain)
		if err != nil {
			return APIResponse{StatusCode: http.StatusNotFound, Message: err.Error()}
		}
		return APIResponse{StatusCode: http.StatusOK, Response: scan}
	} else {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/scan only accepts POST and GET requests"}
	}
}

// MaxHostnames is the maximum number of hostnames that can be specified for a single domain's TLS policy.
const MaxHostnames = 8

// Extracts relevant parameters from http.Request for a POST to /api/queue into PolicySubmission
// If MTASTS is set, doesn't try to extract hostnames. Otherwise, expects between 1 and MaxHostnames
// valid hostnames to be given in |r|.
func getDomainParams(r *http.Request) (models.PolicySubmission, error) {
	name, err := getASCIIDomain(r)
	if err != nil {
		return models.PolicySubmission{}, err
	}
	email, err := getParam("email", r)
	if err != nil {
		email = validationAddress(name)
	}
	mtasts := r.FormValue("mta-sts")
	domain := models.PolicySubmission{
		Domain:       name,
		ContactEmail: email,
		MTASTS:       mtasts == "on",
	}
	if !domain.MTASTS {
		p := policy.TLSPolicy{Mode: "testing", MXs: make([]string, 0)}
		for _, hostname := range r.PostForm["hostnames"] {
			if len(hostname) == 0 {
				continue
			}
			if !validDomainName(strings.TrimPrefix(hostname, ".")) {
				return domain, fmt.Errorf("Hostname %s is invalid", hostname)
			}
			p.MXs = append(p.MXs, hostname)
		}
		if len(p.MXs) == 0 {
			return domain, fmt.Errorf("No MX hostnames supplied for domain %s", name)
		}
		if len(p.MXs) > MaxHostnames {
			return domain, fmt.Errorf("No more than 8 MX hostnames are permitted")
		}
		domain.Policy = &p
	}
	return domain, nil
}

// Queue is the handler for /api/queue
//   POST /api/queue?domain=<domain>
//        domain: Mail domain to queue a TLS policy for.
//				mta_sts: "on" if domain supports MTA-STS, else "".
//        hostnames: List of MX hostnames to put into this domain's TLS policy. Up to 8.
//        Sets models.Domain object as response.
//        weeks (optional, default 4): How many weeks is this domain queued for.
//        email (optional): Contact email associated with domain.
//   GET  /api/queue?domain=<domain>
//        Sets models.Domain object as response.
func (api API) Queue(r *http.Request) APIResponse {
	// POST: Insert this domain into the queue
	if r.Method != http.MethodPost {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/queue only accepts POST requests"}
	}
	domain, err := getDomainParams(r)
	if err != nil {
		return badRequest(err.Error())
	}
	if !domain.CanUpdate(api.Database.Policies) {
		return badRequest("submission already exists")
	}
	ok, msg := domain.HasValidScan(api.Database)
	if !ok {
		return badRequest(msg)
	}
	token, err := domain.InitializeWithToken(api.Database.PendingPolicies, api.Database)
	if err != nil {
		return serverError(err.Error())
	}
	if err = api.Emailer.SendValidation(&domain, token); err != nil {
		log.Print(err)
		return serverError("Unable to send validation e-mail")
	}
	return APIResponse{
		StatusCode: http.StatusOK,
		Response:   fmt.Sprintf("Thank you for submitting your domain. Please check postmaster@%s to validate that you control the domain.", domain.Domain),
	}
}

// Validate handles requests to /api/validate
//   POST /api/validate
//        token: token to validate/redeem
//        Sets the queued domain name as response.
func (api API) Validate(r *http.Request) APIResponse {
	token, err := getParam("token", r)
	if err != nil {
		return APIResponse{StatusCode: http.StatusBadRequest, Message: err.Error()}
	}
	if r.Method != http.MethodPost {
		return APIResponse{StatusCode: http.StatusMethodNotAllowed,
			Message: "/api/validate only accepts POST requests"}
	}
	tokenData := models.Token{Token: token}
	domain, userErr, dbErr := tokenData.Redeem(api.Database.PendingPolicies, api.Database.Policies, api.Database)
	if userErr != nil {
		return badRequest(userErr.Error())
	}
	if dbErr != nil {
		return serverError(dbErr.Error())
	}
	return APIResponse{StatusCode: http.StatusOK, Response: domain}
}

// Retrieve "domain" parameter from request as ASCII
// If fails, returns an error.
func getASCIIDomain(r *http.Request) (string, error) {
	domain, err := getParam("domain", r)
	if err != nil {
		return domain, err
	}
	ascii, err := idna.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("could not convert domain %s to ASCII (%s)", domain, err)
	}
	return ascii, nil
}

// Retrieves and lowercases `param` as a query parameter from `http.Request` r.
// If fails, then returns an error.
func getParam(param string, r *http.Request) (string, error) {
	unicode := r.FormValue(param)
	if unicode == "" {
		return "", fmt.Errorf("query parameter %s not specified", param)
	}
	return strings.ToLower(unicode), nil
}

// Retrieves `param` as a query parameter from `http.Request` r, and tries to cast it as
// a number between [lowInc, highExc). If fails, then returns an error.
// If `param` isn't specified, return defaultNum.
func getInt(param string, r *http.Request, lowInc int, highExc int, defaultNum int) (int, error) {
	unicode := r.FormValue(param)
	if unicode == "" {
		return defaultNum, nil
	}
	n, err := strconv.Atoi(unicode)
	if err != nil {
		return -1, err
	}
	if n < lowInc {
		return n, fmt.Errorf("expected query parameter %s to be more than or equal to %d, was %d", param, lowInc, n)
	}
	if n >= highExc {
		return n, fmt.Errorf("expected query parameter %s to be less than %d, was %d", param, highExc, n)
	}
	return n, nil
}

// Writes `v` as a JSON object to http.ResponseWriter `w`. If an error
// occurs, writes `http.StatusInternalServerError` to `w`.
func (api *API) writeJSON(w http.ResponseWriter, apiResponse APIResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiResponse.StatusCode)
	b, err := json.MarshalIndent(apiResponse, "", "  ")
	if err != nil {
		msg := fmt.Sprintf("Internal error: could not format JSON. (%s)\n", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s\n", b)
}

func (api *API) parseTemplates() {
	names := []string{"default", "scan"}
	api.Templates = make(map[string]*template.Template)
	for _, name := range names {
		path := fmt.Sprintf("views/%s.html.tmpl", name)
		tmpl, err := template.ParseFiles(path)
		if err != nil {
			raven.CaptureError(err, nil)
			log.Fatal(err)
		}
		api.Templates[name] = tmpl
	}
}

func (api *API) writeHTML(w http.ResponseWriter, apiResponse APIResponse) {
	// Add some additional useful fields for use in templates.
	data := struct {
		APIResponse
		BaseURL    string
		StatusText string
	}{
		APIResponse: apiResponse,
		BaseURL:     os.Getenv("FRONTEND_WEBSITE_LINK"),
		StatusText:  http.StatusText(apiResponse.StatusCode),
	}
	if apiResponse.templateName == "" {
		apiResponse.templateName = "default"
	}
	tmpl, ok := api.Templates[apiResponse.templateName]
	if !ok {
		err := fmt.Errorf("Template not found: %s", apiResponse.templateName)
		raven.CaptureError(err, nil)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(apiResponse.StatusCode)
	err := tmpl.Execute(w, data)
	if err != nil {
		log.Println(err)
		raven.CaptureError(err, nil)
	}
}

func badRequest(format string, a ...interface{}) APIResponse {
	return APIResponse{
		StatusCode: http.StatusBadRequest,
		Message:    fmt.Sprintf(format, a...),
	}
}

func serverError(format string, a ...interface{}) APIResponse {
	return APIResponse{
		StatusCode: http.StatusInternalServerError,
		Message:    fmt.Sprintf(format, a...),
	}
}
