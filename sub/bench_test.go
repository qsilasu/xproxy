package sub

import (
	"fmt"
	"testing"
)

func BenchmarkParseRaw(b *testing.B) {
	var lines string
	for i := range 50 {
		lines += fmt.Sprintf("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@%d.%d.%d.%d:8388#Node%d\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF, i)
	}
	data := []byte(lines)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(data, FmtRaw)
	}
}

func BenchmarkParseThenGenerateClash(b *testing.B) {
	var lines string
	for i := range 50 {
		lines += fmt.Sprintf("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@%d.%d.%d.%d:8388#Node%d\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF, i)
	}
	sub, _ := Parse([]byte(lines), FmtRaw)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Generate(sub, FmtClash)
	}
}

func BenchmarkDetect(b *testing.B) {
	data := []byte("proxies:\n  - name: test\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pass\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Detect(data)
	}
}

func BenchmarkBase64Encode(b *testing.B) {
	var lines string
	for i := range 50 {
		lines += fmt.Sprintf("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@%d.%d.%d.%d:8388#Node%d\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF, i)
	}
	sub, _ := Parse([]byte(lines), FmtRaw)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Generate(sub, FmtBase64)
	}
}
