package optimization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// func TestUrlEncode(t *testing.T) {
// 	type args struct {
// 		s string
// 	}
// 	tests := []struct {
// 		name       string
// 		args       args
// 		wantResult string
// 	}{
// 		{
// 			name: "test - single",
// 			args: args{
// 				s: "a",
// 			},
// 			wantResult: "%61",
// 		},
// 		{
// 			name: "test - quaternary",
// 			args: args{
// 				s: fmt.Sprintf("%c", 0x2fffff),
// 			},
// 			wantResult: "",
// 		},
// 		{
// 			name: "test - triple",
// 			args: args{
// 				s: "환",
// 			},
// 			wantResult: "%ED%99%98",
// 		},
// 		{
// 			name: "test - double",
// 			args: args{
// 				s: "Ǳ",
// 			},
// 			wantResult: "%C7%B1",
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if gotResult := UrlEncode(tt.args.s); gotResult != tt.wantResult {
// 				t.Errorf("UrlEncode() = %v, want %v", gotResult, tt.wantResult)
// 			}
// 		})
// 	}
// }

func TestUrlEncode(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name       string
		args       args
		wantResult string
	}{
		{
			name: "test - single",
			args: args{
				s: "a",
			},
			wantResult: "%61",
		},
		{
			name: "test - triple",
			args: args{
				s: "환",
			},
			wantResult: "%ED%99%98",
		},
		{
			name: "test - double",
			args: args{
				s: "Ǳ",
			},
			wantResult: "%C7%B1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantResult, UrlEncode(tt.args.s))
		})
	}
}
