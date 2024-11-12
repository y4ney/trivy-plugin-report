package markdown

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/y4ney/trivy-plugin-report/internal/utils"
	"testing"
)

func TestExport(t *testing.T) {
	type args struct {
		report   *types.Report
		filePath string
	}
	report, err := utils.ReadJSONFromFile("testdata/kube-hunter.json")
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
				filePath: "testdata/kube-hunter.html",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Export(tt.args.report, tt.args.filePath); (err != nil) != tt.wantErr {
				t.Errorf("Export() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
