package waf_service

import (
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSetImportScalarSignedWidths(t *testing.T) {
	for _, sample := range []interface{}{int(0), int8(0), int16(0), int32(0), int64(0)} {
		typ := reflect.TypeOf(sample)
		t.Run(typ.String(), func(t *testing.T) {
			limit := new(big.Int).Lsh(big.NewInt(1), uint(typ.Bits()-1))
			min := new(big.Int).Neg(new(big.Int).Set(limit))
			max := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
			for _, valid := range []string{min.String(), max.String(), "0", "-1", "+1"} {
				field := reflect.New(typ).Elem()
				if err := setImportScalar(field, valid); err != nil {
					t.Fatalf("valid boundary rejected: %v", err)
				}
				want, _ := strconv.ParseInt(valid, 10, typ.Bits())
				if field.Int() != want {
					t.Fatalf("got %d, want %d", field.Int(), want)
				}
			}
			for _, invalid := range []string{
				new(big.Int).Sub(min, big.NewInt(1)).String(),
				new(big.Int).Add(max, big.NewInt(1)).String(),
				"", "invalid-secret", "1.5", "1e3", "0x10", " 1", "1 ",
			} {
				assertImportScalarRejected(t, typ, invalid)
			}
		})
	}
}

func TestSetImportScalarUnsignedWidths(t *testing.T) {
	for _, sample := range []interface{}{uint(0), uint8(0), uint16(0), uint32(0), uint64(0), uintptr(0)} {
		typ := reflect.TypeOf(sample)
		t.Run(typ.String(), func(t *testing.T) {
			limit := new(big.Int).Lsh(big.NewInt(1), uint(typ.Bits()))
			max := new(big.Int).Sub(new(big.Int).Set(limit), big.NewInt(1))
			for _, valid := range []string{"0", "1", max.String()} {
				field := reflect.New(typ).Elem()
				if err := setImportScalar(field, valid); err != nil {
					t.Fatalf("valid boundary rejected: %v", err)
				}
				want, _ := strconv.ParseUint(valid, 10, typ.Bits())
				if field.Uint() != want {
					t.Fatalf("got %d, want %d", field.Uint(), want)
				}
			}
			for _, invalid := range []string{limit.String(), "-1", "", "invalid-secret", "1.5", "0x10", " 1"} {
				assertImportScalarRejected(t, typ, invalid)
			}
		})
	}
}

func TestSetImportScalarStringAndBool(t *testing.T) {
	var text string
	for _, valid := range []string{"", " original text ", "中文"} {
		if err := setImportScalar(reflect.ValueOf(&text).Elem(), valid); err != nil || text != valid {
			t.Fatal("string value was not preserved")
		}
	}
	for _, valid := range []string{"true", "false", "1", "0", "TRUE", "FALSE"} {
		var value bool
		if err := setImportScalar(reflect.ValueOf(&value).Elem(), valid); err != nil {
			t.Fatalf("valid bool rejected: %v", err)
		}
		want, _ := strconv.ParseBool(valid)
		if value != want {
			t.Fatalf("got %v, want %v", value, want)
		}
	}
	for _, invalid := range []string{"", "2", "invalid-secret", " true"} {
		assertImportScalarRejected(t, reflect.TypeOf(false), invalid)
	}
}

func TestSetImportScalarFloatWidths(t *testing.T) {
	for _, sample := range []interface{}{float32(0), float64(0)} {
		typ := reflect.TypeOf(sample)
		t.Run(typ.String(), func(t *testing.T) {
			max, smallest := math.MaxFloat64, math.SmallestNonzeroFloat64
			overflow := "1e309"
			if typ.Bits() == 32 {
				max, smallest, overflow = math.MaxFloat32, math.SmallestNonzeroFloat32, "1e39"
			}
			for _, valid := range []string{
				"0", "-1.25", "1.5e2",
				strconv.FormatFloat(max, 'g', -1, typ.Bits()),
				strconv.FormatFloat(-max, 'g', -1, typ.Bits()),
				strconv.FormatFloat(smallest, 'g', -1, typ.Bits()),
			} {
				field := reflect.New(typ).Elem()
				if err := setImportScalar(field, valid); err != nil {
					t.Fatalf("valid float rejected: %v", err)
				}
				want, _ := strconv.ParseFloat(valid, typ.Bits())
				if field.Float() != want {
					t.Fatalf("got %v, want %v", field.Float(), want)
				}
			}
			for _, invalid := range []string{"", "invalid-secret", overflow, "-" + overflow, "NaN", "Inf", "+Inf", "-Inf", " 1"} {
				assertImportScalarRejected(t, typ, invalid)
			}
		})
	}
}

func TestSetImportScalarUnsupportedAndUnwritable(t *testing.T) {
	for _, sample := range []interface{}{
		struct{}{}, []string{}, [1]int{}, map[string]string{}, (*int)(nil), complex64(0), complex128(0),
		make(chan int), (func())(nil),
	} {
		typ := reflect.TypeOf(sample)
		t.Run(typ.String(), func(t *testing.T) {
			assertImportScalarRejected(t, typ, "invalid-secret")
		})
	}
	var value interface{}
	if err := setImportScalar(reflect.ValueOf(&value).Elem(), "invalid-secret"); err == nil {
		t.Fatal("interface field accepted")
	}
	for _, field := range []reflect.Value{reflect.Value{}, reflect.ValueOf(1)} {
		if err := setImportScalar(field, "invalid-secret"); err == nil {
			t.Fatal("unwritable field accepted")
		}
	}
}

func TestSetImportScalarNamedTypes(t *testing.T) {
	type signed int64
	type unsigned uint16
	type text string
	type flag bool
	type number float32
	for _, tc := range []struct {
		initial interface{}
		input   string
		want    interface{}
	}{
		{signed(0), "9223372036854775807", signed(math.MaxInt64)},
		{unsigned(0), "65535", unsigned(math.MaxUint16)},
		{text(""), "unchanged", text("unchanged")},
		{flag(false), "true", flag(true)},
		{number(0), "1.25", number(1.25)},
	} {
		field := reflect.New(reflect.TypeOf(tc.initial)).Elem()
		if err := setImportScalar(field, tc.input); err != nil || !reflect.DeepEqual(field.Interface(), tc.want) {
			t.Fatalf("named scalar conversion failed: %v", err)
		}
	}
}

func assertImportScalarRejected(t *testing.T, typ reflect.Type, input string) {
	t.Helper()
	field := reflect.New(typ).Elem()
	switch field.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		field.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		field.SetUint(7)
	case reflect.Bool:
		field.SetBool(true)
	case reflect.Float32, reflect.Float64:
		field.SetFloat(7)
	}
	before := field.Interface()
	err := setImportScalar(field, input)
	if err == nil {
		t.Fatal("invalid value or unsupported type accepted")
	}
	if input != "" && strings.Contains(err.Error(), input) {
		t.Fatal("error contains the input value")
	}
	if !reflect.DeepEqual(field.Interface(), before) {
		t.Fatal("failed conversion changed the field")
	}
}
