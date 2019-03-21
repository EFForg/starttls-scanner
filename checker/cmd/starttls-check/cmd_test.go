package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/EFForg/starttls-backend/checker"
)

func TestUpdateStats(t *testing.T) {
	out = new(bytes.Buffer)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `1,foo,example1.com
2,bar,example2.com
3,baz,example3.com`)
	}))
	defer ts.Close()

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"starttls-checker", "--url", ts.URL, "--aggregate=true", "--column=2"}

	// @TODO make this faster
	main()
	got := out.(*bytes.Buffer).String()
	expected := checker.DomainTotals{
		Time:      time.Time{},
		Source:    ts.URL,
		Attempted: 3,
	}.String()
	expected = strings.ReplaceAll(expected, time.Time{}.String(), ".*")
	re := regexp.MustCompile(expected)

	if !re.MatchString(got) {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, got)
	}
}