package filter

import (
	"io/ioutil"
	"testing"
)

type VersionVulnerability struct {
	version    string
	vulnerable bool
}

func TestFilterJndi(t *testing.T) {
	for _, item := range []VersionVulnerability{
		{"2.1", true},
		{"2.2", true},
		{"2.3", true},
		{"2.4", true},
		{"2.4.1", true},
		{"2.5", true},
		{"2.6", true},
		{"2.6.1", true},
		{"2.6.2", true},
		{"2.7", true},
		{"2.8", true},
		{"2.8.1", true},
		{"2.8.2", true},
		{"2.9.0", true},
		{"2.9.1", true},
		{"2.10.0", true},
		{"2.11.0", true},
		{"2.11.1", true},
		{"2.11.2", true},
		{"2.12.0", true},
		{"2.12.1", true},
		{"2.12.2", false},
		{"2.13.0", true},
		{"2.13.1", true},
		{"2.13.2", true},
		{"2.13.3", true},
		{"2.13-3-debian", true},
		{"2.14.0", true},
		{"2.14.1", true},
		{"2.15.0", true},
		{"2.16.0", false},
		{"2.16.0-debian", false},
		{"2.17.0", false},
	} {
		file := "../testdata/JndiManager.class-" + item.version
		buf, err := ioutil.ReadFile(file)
		if err != nil {
			t.Logf("can't open %s: %v", file, err)
			continue
		}
		//goland:noinspection SpellCheckingInspection
		if verdict := IsVulnerableClass(buf, "jndimanager.class", true); (verdict != "") != item.vulnerable {
			if item.vulnerable {
				t.Errorf("found %s not to be vulnerable (but it is)", file)
			} else {
				t.Errorf("found %s to be vulnerable (but it is not)", file)
			}
		} else {
			t.Logf("%s: %s", file, verdict)
		}
	}
}

func TestFilterSocketNode(t *testing.T) {
	for _, item := range []VersionVulnerability{
		{"1.2.4", true},
		{"1.2.5", true},
		{"1.2.6", true},
		{"1.2.7", true},
		{"1.2.8", true},
		{"1.2.9", true},
		{"1.2.11", true},
		{"1.2.12", true},
		{"1.2.13", true},
		{"1.2.14", true},
		{"1.2.15", true},
		{"1.2.16", true},
		{"1.2.17", true},
		{"1.2.17-debian", false},
	} {
		file := "../testdata/SocketNode.class-" + item.version
		buf, err := ioutil.ReadFile(file)
		if err != nil {
			t.Logf("can't open %s: %v", file, err)
			continue
		}
		//goland:noinspection SpellCheckingInspection
		if verdict := IsVulnerableClass(buf, "socketnode.class", true); (verdict != "") != item.vulnerable {
			if item.vulnerable {
				t.Errorf("found %s not to be vulnerable (but it is)", file)
			} else {
				t.Errorf("found %s to be vulnerable (but it is not)", file)
			}
		} else {
			t.Logf("%s: %s", file, verdict)
		}
	}
}
