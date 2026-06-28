package postgresql

import (
	"testing"

	"github.com/blang/semver"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
)

func TestFindStringSubmatchMap(t *testing.T) {

	resultMap := findStringSubmatchMap(`(?si).*\$(?P<Body>.*)\$.*`, "aa $something_to_extract$ bb")

	assert.Equal(t,
		resultMap,
		map[string]string{
			"Body": "something_to_extract",
		},
	)
}

func TestQuoteTableName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple table name",
			input:    "users",
			expected: `"users"`,
		},
		{
			name:     "table name with schema",
			input:    "test.users",
			expected: `"test"."users"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := quoteTableName(tt.input)
			if actual != tt.expected {
				t.Errorf("quoteTableName() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

var (
	pg15 = semver.MustParse("15.0.0")
	pg16 = semver.MustParse("16.0.0")
	pg17 = semver.MustParse("17.0.0")
)

func TestArePrivilegesEqual(t *testing.T) {

	type PrivilegesTestObject struct {
		name      string
		d         *schema.ResourceData
		granted   *schema.Set
		wanted    *schema.Set
		ver       semver.Version
		assertion bool
	}

	tt := []PrivilegesTestObject{
		{
			"database ALL on pg15",
			buildResourceData("database", t),
			buildPrivilegesSet("CONNECT", "CREATE", "TEMPORARY"),
			buildPrivilegesSet("ALL"),
			pg15,
			true,
		},
		{
			"database partial != USAGE",
			buildResourceData("database", t),
			buildPrivilegesSet("CREATE", "USAGE"),
			buildPrivilegesSet("USAGE"),
			pg15,
			false,
		},
		{
			"table ALL without MAINTAIN on pg15",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"),
			buildPrivilegesSet("ALL"),
			pg15,
			true,
		},
		{
			"table ALL with MAINTAIN on pg16",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"),
			buildPrivilegesSet("ALL"),
			pg16,
			true,
		},
		{
			// Extra privileges beyond the known set for a version are tolerated
			// (e.g. a future PG version adds a new privilege), so no drift.
			"table ALL with extra unknown privilege - no drift",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"),
			buildPrivilegesSet("ALL"),
			pg15,
			true,
		},
		{
			// MAINTAIN is not a privilege before PG17, so GRANT ALL yields 7
			// privileges and a 7-privilege set matches ALL on pg16 without drift.
			"table ALL without MAINTAIN on pg16 - no drift",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"),
			buildPrivilegesSet("ALL"),
			pg16,
			true,
		},
		{
			// On PG17 MAINTAIN is part of ALL, so GRANT ALL yields 8 privileges
			// and the full 8-privilege set matches ALL without drift.
			"table ALL with MAINTAIN on pg17 - no drift",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"),
			buildPrivilegesSet("ALL"),
			pg17,
			true,
		},
		{
			// On PG17 MAINTAIN is part of ALL, so a granted set missing MAINTAIN
			// is not equal to ALL and must report drift.
			"table ALL missing MAINTAIN on pg17 - drift",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"),
			buildPrivilegesSet("ALL"),
			pg17,
			false,
		},
		{
			"table partial != multi",
			buildResourceData("table", t),
			buildPrivilegesSet("SELECT"),
			buildPrivilegesSet("SELECT, INSERT"),
			pg15,
			false,
		},
		{
			"schema ALL on pg15",
			buildResourceData("schema", t),
			buildPrivilegesSet("CREATE", "USAGE"),
			buildPrivilegesSet("ALL"),
			pg15,
			true,
		},
		{
			"schema partial != ALL",
			buildResourceData("schema", t),
			buildPrivilegesSet("CREATE"),
			buildPrivilegesSet("ALL"),
			pg15,
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.Set("privileges", tc.wanted)
			assert.NoError(t, err)
			equal := resourcePrivilegesEqual(tc.granted, &DBConnection{version: tc.ver}, tc.d)
			assert.Equal(t, tc.assertion, equal)
		})
	}
}

func buildPrivilegesSet(grants ...any) *schema.Set {
	return schema.NewSet(schema.HashString, grants)
}

func buildResourceData(objectType string, t *testing.T) *schema.ResourceData {
	var testSchema = map[string]*schema.Schema{
		"object_type": {Type: schema.TypeString},
		"privileges": {
			Type: schema.TypeSet,
			Elem: &schema.Schema{Type: schema.TypeString},
			Set:  schema.HashString,
		},
	}

	m := make(map[string]any)
	m["object_type"] = objectType
	return schema.TestResourceDataRaw(t, testSchema, m)
}
