package rdx

import (
	"fmt"
	"github.com/drpcorg/chotki/protocol"
	"github.com/stretchr/testify/assert"
	"math"
	"strconv"
	"testing"
)

func FuzzF(f *testing.F) {
	f.Fuzz(func(t *testing.T, val float64) {
		tlv := Ftlv(val)
		if tlv != nil {
			if newVal := Fnative(tlv); math.Abs(val-newVal) >= 1e-9 {
				t.Errorf("Before %f, After %f", val, newVal)
			}
		}
	})
}

func FuzzI(f *testing.F) {
	f.Fuzz(func(t *testing.T, val int64) {
		tlv := Itlv(val)
		if tlv != nil {
			if newVal := Inative(tlv); newVal != val {
				t.Errorf("Before %d, After %d", val, newVal)
			}
		}
	})
}

func FuzzR(f *testing.F) {
	f.Fuzz(func(t *testing.T, val uint64) {
		valID := ID(val)
		tlv := Rtlv(valID)
		if tlv != nil {
			newVal := Rnative(tlv)
			if newVal != valID {
				t.Errorf("Before %s, After %s", valID, newVal)
			}
		}
	})
}

func FuzzS(f *testing.F) {
	f.Fuzz(func(t *testing.T, val string) {
		tlv := Stlv(val)
		if tlv != nil {
			newVal := Snative(tlv)
			if newVal != val {
				t.Errorf("Before %s, After %s", val, newVal)
			}
		}
	})
}

func FuzzT(f *testing.F) {
	f.Fuzz(func(t *testing.T, val string) {
		tlv := Tparse(val)
		if tlv != nil {
			newVal := Tstring(tlv)
			if newVal != val && newVal != "null" {
				t.Errorf("Before %s, After %s", val, newVal)
			}
		}
	})
}

func FuzzFParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, val string) {
		tlv := Fparse(val)
		if len(tlv) == 0 {
			return
		}
		newVal := Fstring(tlv)
		fVal, _ := strconv.ParseFloat(val, 64)
		if fmt.Sprintf("%f", fVal) != newVal {
			t.Errorf("Before %s, After %s", val, newVal)
		}
	})
}

func FuzzIParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, val string) {
		tlv := Iparse(val)
		if len(tlv) != 0 {
			newVal := Istring(tlv)
			iVal, _ := strconv.ParseInt(val, 10, 64)
			if fmt.Sprintf("%d", iVal) != newVal {
				t.Errorf("Before %s, After %s", val, newVal)
			}
		}
	})
}

func FuzzTLV(f *testing.F) {
	f.Fuzz(func(t *testing.T, body []byte, rev int64, src uint64) {
		tlv := FIRSTtlv(rev, src, body)
		time1, src1, val := ParseFIRST(tlv)
		assert.Equal(t, rev, time1)
		assert.Equal(t, src, src1)
		assert.Equal(t, body, val)
	})
}

func FuzzSParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, str string) {
		tlv := Stlv(str)
		quoted := Sstring(tlv)
		unquoted := Snative(Sparse(quoted))
		assert.Equal(t, str, unquoted)
		assert.Equal(t, str, Snative(tlv))

	})
}

func FuzzTParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, val string) {
		tlv := Tparse(val)
		if len(tlv) != 0 {
			newVal := Tstring(tlv)

			if val != newVal && newVal != "null" {
				t.Errorf("Before %s, After %s", val, newVal)
			}
		}
	})
}

func FuzzNtlv(f *testing.F) {
	f.Fuzz(func(t *testing.T, u uint64) {
		fact := Ntlv(u)
		correct := protocol.Record(Term, ZipUint64Pair(u, 0))
		assert.Equal(t, correct, fact)
	})
}

func FuzzZtlv(f *testing.F) {
	f.Fuzz(func(t *testing.T, i int64) {
		fact := Ztlv(i)
		correct := Itlve(0, 0, i)
		assert.Equal(t, correct, fact)
	})
}

func FuzzMergeFirst(f *testing.F) {
	f.Fuzz(func(t *testing.T, tlv1 []byte, tlv2 []byte, rdt byte) {
		tlv1 = FIRSTtlv(0, 0, tlv1)
		tlv2 = FIRSTtlv(0, 0, tlv2)
		if !Xvalid(rdt, tlv1) || !Xvalid(rdt, tlv2) {
			return
		}
		tlvMerge1 := MergeFIRST([][]byte{tlv1, tlv2})
		tlvMerge2 := MergeFIRST([][]byte{tlv2, tlv1})
		assert.Equal(t, tlvMerge1, tlvMerge2)
		assert.Equal(t, tlv1, MergeFIRST([][]byte{tlv1, tlv1}))
		assert.Equal(t, tlv2, MergeFIRST([][]byte{tlv2, tlv2}))
	})
}

func FuzzMergeZ(f *testing.F) {
	f.Fuzz(func(t *testing.T, i1, i2 int64) {
		tlv1 := Ztlv(i1)
		tlv2 := Ztlv(i2)
		tlvMerge1 := Zmerge([][]byte{tlv1, tlv2})
		tlvMerge2 := Zmerge([][]byte{tlv2, tlv1})
		assert.Equal(t, Znative(tlvMerge1), Znative(tlvMerge2))
		assert.Equal(t, Znative(tlv1), Znative(Zmerge([][]byte{tlv1, tlv1})))
		assert.Equal(t, Znative(tlv2), Znative(Zmerge([][]byte{tlv2, tlv2})))
	})
}

func FuzzMergeN(f *testing.F) {
	f.Fuzz(func(t *testing.T, u1, u2 uint64) {
		tlv1 := Ntlv(u1)
		tlv2 := Ntlv(u2)
		tlvMerge1 := Nmerge([][]byte{tlv1, tlv2})
		tlvMerge2 := Nmerge([][]byte{tlv2, tlv1})
		assert.Equal(t, Nnative(tlvMerge1), Nnative(tlvMerge2))
		assert.Equal(t, Nnative(tlv1), Nnative(Nmerge([][]byte{tlv1, tlv1})))
		assert.Equal(t, Nnative(tlv2), Nnative(Nmerge([][]byte{tlv2, tlv2})))
	})
}
