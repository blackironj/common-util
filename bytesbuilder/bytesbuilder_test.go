package bytesbuilder

import (
	"bytes"
	"testing"
)

const (
	originDataForB64 = "Hello base64"
	base64Str        = "SGVsbG8gYmFzZTY0"
	originDataForB58 = "Hello base58"
	base58Str        = "2NEpo7TZRXJTtJ5BD"
	originDataFroHex = "Hello Hex"
	hexStr           = "0x48656c6c6f20486578"
)

func TestByteBuilder_AppendBaseXX(t *testing.T) {
	builder := NewBuilder()

	builder.AppendBase64(base64Str)
	builder.AppendBase58(base58Str)

	bytesData := builder.GetBytes()
	strData := string(bytesData)

	if strData != originDataForB64+originDataForB58 {
		t.Errorf("TestByteBuilder_AppendBaseXX failed: want '%s', got '%s'",
			originDataForB64+originDataForB58, strData)
	}
}

func TestByteBuilder_AppendHex(t *testing.T) {
	builder := NewBuilder()

	builder.AppendHex(hexStr)

	bytesData := builder.GetBytes()
	strData := string(bytesData)

	if strData != originDataFroHex {
		t.Errorf("TestByteBuilder_AppendHex failed: want '%s', got '%s'",
			originDataFroHex, strData)
	}
}

func TestByteBuilder_CommonAppend(t *testing.T) {
	builder := NewBuilder()

	var u8 uint8
	var u8Arr []uint8
	var u32 uint32
	var u64 uint64
	var str string

	u8 = 0x11
	u8Arr = []uint8{0x99, 0x99}
	u32 = 0x11223344
	u64 = 0x1122334455667788
	str = "AAA"

	builder.Append(u8)
	builder.Append(u8Arr)
	builder.Append(u32)
	builder.Append(u64)
	builder.Append(str)

	expected := []byte{0x11, 0x99, 0x99, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x41, 0x41, 0x41}
	bytesData := builder.GetBytes()

	if !bytes.Equal(expected, bytesData) {
		t.Errorf("TestByteBuilder_CommonAppend failed: want '%x', got '%x'",
			expected, bytesData)
	}
}
