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
		txt []string
		ok  bool
	}{
		{[]string{"v=STSv1; id=1234", "v=STSv1; id=5678"}, false},
		{[]string{"v=STSv1; id=20171114T070707;"}, true},
		{[]string{"v=STSv1; id=;"}, false},
		{[]string{"v=STSv1; id=###;"}, false},
		{[]string{"v=spf1 a -all"}, false},
	}
	for _, test := range tests {
		if err := checkMTASTSRecord(test.txt); (err != nil) == test.ok {
			t.Errorf("checkMTASTSDNS(%v) = %v", test.txt, err)
		}
	}
}
