package checker

import (
	"reflect"
	"testing"
)

func TestParseTXT(t *testing.T) {
	tests := []struct {
		txt  string
		want map[string]string
	}{
		{"", map[string]string{}},
		{"v=STSv1; foo;", map[string]string{
			"v": "STSv1",
		}},
		{"v=STSv1; id=20171114T070707;", map[string]string{
			"v":  "STSv1",
			"id": "20171114T070707",
		}},
	}
	for _, test := range tests {
		if got := parseTXT(test.txt); !reflect.DeepEqual(got, test.want) {
			t.Errorf("parseTXT(%s) = %v, want %v", test.txt, got, test.want)
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
