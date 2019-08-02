package util

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"github.com/btcsuite/btcutil/base58"
)

type ByteBuilder struct {
	BytesArr []byte
}

func NewBytesBuilder() *ByteBuilder {
	b := ByteBuilder{}
	return &b
}

func (builder *ByteBuilder) Clear() {
	builder.BytesArr = nil
}

//TODO : exception handling

func (builder *ByteBuilder) Append(data interface{}) {
	var byteData []byte
	switch data.(type) {
	case string:
		b := data.(string)
		byteData = []byte(b)
	case uint8:
		byteData = append(byteData, data.(uint8))
	case []uint8:
		byteData = data.([]byte)
	case uint32:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, data.(uint32))
		byteData = b
	case uint64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, data.(uint64))
		byteData = b
	}
	builder.BytesArr = append(builder.BytesArr, byteData...)
}

func (builder *ByteBuilder) AppendHex(hexStr string) {
	data, _ := hex.DecodeString(hexStr[2:])
	builder.BytesArr = append(builder.BytesArr, data...)
}

func (builder *ByteBuilder) AppendBase64(b64Str string) {
	decodedData, _ := base64.StdEncoding.DecodeString(b64Str)
	builder.BytesArr = append(builder.BytesArr, decodedData...)
}

func (builder *ByteBuilder) AppendBase58(b58Str string) {
	decodedData := base58.Decode(b58Str)
	builder.BytesArr = append(builder.BytesArr, decodedData...)
}

func (builder *ByteBuilder) GetBytes() []byte {
	return builder.BytesArr
}
