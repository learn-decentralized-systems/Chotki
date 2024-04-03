package rdx

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRDX_Parse(t *testing.T) {
	// todo
	// - separators
	// - more checks
	// - FIRST, object
	cases := map[string]string{
		"12345":                      "12345",
		"{1: 2}":                     "{1:2}",
		"{1: {2 : 4}}":               "{1:{2:4}}",
		"[ 1, 2, 3]":                 "[1,2,3]",
		" [ \"string here\", 1 ,2 ]": "[\"string here\",1,2]",
		"{1f8-a364: 3 }":             "{1f8-a364:3}",
		"{1f8-a364, 3,4, \"five\" }": "{1f8-a364,3,4,\"five\"}",
	}
	for in, out := range cases {
		rdx, err := ParseRDX([]byte(in))
		assert.Nil(t, err)
		assert.Equal(t, out, rdx.String())
	}
}