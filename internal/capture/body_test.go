package capture

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"netlens/internal/model"
)

func TestFullBodyLosslessPaging(t *testing.T) {
	for _, data := range [][]byte{[]byte("<html>错误：smallCode 已使用</html>"), []byte(strings.Repeat("你好🙂", 10000) + "tail"), {0xff, 0, 1, 2, 3}, []byte("hello\x00world")} {
		v := InspectBody(model.Body{Data: data, Size: int64(len(data))}, http.Header{"Content-Type": {"text/html"}})
		var got []byte
		for offset := 0; ; {
			page, err := v.Page(offset, 7)
			if err != nil {
				t.Fatal(err)
			}
			part := []byte(page["text"].(string))
			if page["encoding"] == "base64" {
				part, err = base64.StdEncoding.DecodeString(string(part))
				if err != nil {
					t.Fatal(err)
				}
			}
			got = append(got, part...)
			if page["has_more"] == false {
				break
			}
			offset = page["next_offset"].(int)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("分页读取丢失或改变正文")
		}
	}
	v := InspectBody(model.Body{Data: []byte("你好")}, nil)
	for _, input := range [][2]int{{-1, 10}, {1, 10}, {100, 10}, {0, -1}, {0, 32769}} {
		if _, err := v.Page(input[0], input[1]); err == nil {
			t.Fatalf("接受了非法游标或页长：%v", input)
		}
	}
}

func TestFullBodyCompressionAndCompleteness(t *testing.T) {
	data := []byte(strings.Repeat("完整错误正文", 2000) + `{"smallCode":"same-code"}`)
	for _, encoding := range []string{"gzip", "deflate", "raw-deflate"} {
		var compressed bytes.Buffer
		var writer io.WriteCloser
		switch encoding {
		case "gzip":
			writer = gzip.NewWriter(&compressed)
		case "deflate":
			writer = zlib.NewWriter(&compressed)
		default:
			writer, _ = flate.NewWriter(&compressed, flate.DefaultCompression)
		}
		writer.Write(data)
		writer.Close()
		headerEncoding := encoding
		if encoding == "raw-deflate" {
			headerEncoding = "deflate"
		}
		v := InspectBody(model.Body{Data: compressed.Bytes(), Size: int64(compressed.Len())}, http.Header{"Content-Encoding": {headerEncoding}})
		if !v.Decoded || v.DecodeTruncated || v.DecodeError != "" || !bytes.Equal(v.Data, data) {
			t.Fatalf("压缩正文未完整恢复：%s", encoding)
		}
	}
	var bomb bytes.Buffer
	w := gzip.NewWriter(&bomb)
	w.Write(bytes.Repeat([]byte{'a'}, MaxDecodedBodyBytes+1))
	w.Close()
	v := InspectBody(model.Body{Data: bomb.Bytes()}, http.Header{"Content-Encoding": {"gzip"}})
	if !v.DecodeTruncated || len(v.Data) != MaxDecodedBodyBytes {
		t.Fatal("解压预算未生效或未标注截断")
	}
	v = InspectBody(model.Body{Data: []byte("prefix"), Size: 20, Truncated: true}, nil)
	if !v.CaptureTruncated || !strings.Contains(v.DisplayText(), "采集已截断") || !bytes.Equal(v.Data, []byte("prefix")) {
		t.Fatal("不完整正文未保留已有字节并标注")
	}
	for _, encoding := range []string{"br", "gzip"} {
		v = InspectBody(model.Body{Data: []byte("bad-compressed")}, http.Header{"Content-Encoding": {encoding}})
		if v.DecodeError == "" || v.IsText() || !bytes.Equal(v.Data, []byte("bad-compressed")) {
			t.Fatal("无法解压的原始字节丢失")
		}
	}
}
