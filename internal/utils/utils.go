package utils

import (
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
	"time"
)

// FormatTime 若时间为空，则正常退出并返回空字符串
func FormatTime(t *time.Time, Chinese bool) (string, error) {
	if t == nil {
		return "", nil
	}
	if !Chinese {
		return t.Format("2006-01-02 15:04:05"), nil
	}

	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return "", xerrors.Errorf("failed to load location:%w", err)
	}

	return t.In(location).Format("2006-01-02 15:04:05"), nil
}

// ReadJSONFromFile 从文件中读取 json 文件
func ReadJSONFromFile(filename string) (*types.Report, error) {
	// 若不是 JSON 文件，则正常返回
	if filepath.Ext(filename) != ".json" {
		log.Debugf("%s is not json file", filename)
		return nil, nil
	}

	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, xerrors.Errorf("failed to read file:%w", err)
	}
	log.Debugf("success to read %s", filename)

	// 转化为json
	var report types.Report
	if err = json.Unmarshal(data, &report); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal json:%w", err)
	}
	return &report, nil
}
