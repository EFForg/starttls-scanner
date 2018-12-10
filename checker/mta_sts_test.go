package checker

import (
	"reflect"
	"testing"
)

func TestGetKeyValuePairs(t *testing.T) {
	tests := []struct {
		txt  string
		ld   string
		pd   string
		want map[string]string
	}{
		{"", ";", "=", map[string]string{}},
		{"v=STSv1; foo;", ";", "=", map[string]string{
			"v": "STSv1",
		}},
		{"v=STSv1; id=20171114T070707;", ";", "=", map[string]string{
			"v":  "STSv1",
			"id": "20171114T070707",
		}},
		{"version: STSv1\nmode: enforce\nmx: foo.example.com\nmx: bar.example.com\n\n", "\n", ":", map[string]string{
			"version": "STSv1",
			"mode":    "enforce",
			"mx":      "foo.example.com bar.example.com",
		}},
	}
	for _, test := range tests {
		got := getKeyValuePairs(test.txt, test.ld, test.pd)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("getKeyValuePairs(%s, %s, %s) = %v, want %v",
				test.txt, test.ld, test.pd, got, test.want)
		}
	}
}

func TestCheckMTASTSRecord(t *testing.T) {
	tests := []struct {
		txt    []string
		status CheckStatus
	}{
		{[]string{"v=STSv1; id=1234", "v=STSv1; id=5678"}, Failure},
		{[]string{"v=STSv1; id=20171114T070707;"}, Success},
		{[]string{"v=STSv1; id=;"}, Failure},
		{[]string{"v=STSv1; id=###;"}, Failure},
		{[]string{"v=spf1 a -all"}, Failure},
	}
	for _, test := range tests {
		if result := checkMTASTSRecord(test.txt); result.Status != test.status {
			t.Errorf("checkMTASTSDNS(%v) = %v", test.txt, result)
		}
	}
}
