package excel

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/y4ney/trivy-plugin-report/internal/utils"
	"testing"
)

func TestExport(t *testing.T) {
	type args struct {
		report   *types.Report
		filePath string
		beautify bool
	}
	report, err := utils.ReadJSONFromFile("testdata/vpt_java_test.json")
	if err != nil {
		panic(err)
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "default",
			args: args{
				report:   report,
				filePath: "testdata/vpt_java_test.xlsx",
				beautify: false,
			},
			wantErr: false,
		},
		{
			name: "beautify",
			args: args{
				report:   report,
				filePath: "testdata/vpt_java_test_beautify.xlsx",
				beautify: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Export(tt.args.report, tt.args.filePath, tt.args.beautify); (err != nil) != tt.wantErr {
				t.Errorf("Export() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
