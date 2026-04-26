package url

import (
	"fmt"
	"testing"
)

func BenchmarkParseSS(b *testing.B) {
	raw := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388#MyNode"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(raw)
	}
}

func BenchmarkParseVMess(b *testing.B) {
	raw := "vmess://eyJ2IjoiMiIsInBzIjoiTXlWTWVzcyIsImFkZCI6IjEuMi4zLjQiLCJwb3J0Ijo0NDMsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyJ9"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(raw)
	}
}

func BenchmarkParseVLESS(b *testing.B) {
	raw := "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=tls&type=ws&path=%2Fws#MyVLESS"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(raw)
	}
}

func BenchmarkParseTrojan(b *testing.B) {
	raw := "trojan://mypassword@1.2.3.4:443?security=tls&type=tcp#MyTrojan"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(raw)
	}
}

func BenchmarkGenerateSS(b *testing.B) {
	n, _ := Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388#MyNode")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Generate(n)
	}
}

func BenchmarkParseAndGenerateSS(b *testing.B) {
	raw := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388#MyNode"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, _ := Parse(raw)
		Generate(n)
	}
}

func BenchmarkParseDirtyVMess(b *testing.B) {
	// VMess URL with junk query params — tests cleaning path
	raw := "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6IjEuMi4zLjQiLCJwb3J0Ijo0NDMsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCJ9?remarks=junk&tag=bad"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(raw)
	}
}

// BatchParse benchmarks parsing multiple URLs in sequence.
func BenchmarkBatchParse100(b *testing.B) {
	urls := make([]string, 100)
	for i := range urls {
		urls[i] = fmt.Sprintf("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@%d.%d.%d.%d:8388#Node%d",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF, i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, u := range urls {
			Parse(u)
		}
	}
}
