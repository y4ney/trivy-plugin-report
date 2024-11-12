package utils

import (
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// FormatTime 若时间为空，则正常退出并返回空字符串
func FormatTime(t *time.Time, Chinese bool) string {
	if t == nil {
		return ""
	}
	if !Chinese {
		return t.Format("2006-01-02 15:04:05")
	}

	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		log.Fatal("failed to load location:%w", err)
	}

	return t.In(location).Format("2006-01-02 15:04:05")
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

func Sort(data map[string]int) [][]string {
	var (
		items []struct {
			Key   string
			Value int
		}
		result = make([][]string, len(data))
	)

	for k, v := range data {
		items = append(items, struct {
			Key   string
			Value int
		}{Key: k, Value: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})

	for i, item := range items {
		result[i] = []string{item.Key, strconv.Itoa(item.Value)}
	}

	return result
}

func SetArtifactType(artifactType artifact.Type) string {
	if artifactType == artifact.TypeContainerImage {
		return "容器镜像"
	}
	return string(artifactType)
}

func SetResultClass(resultClass types.ResultClass) string {
	switch resultClass {
	case types.ClassOSPkg:
		return "系统层软件包"
	case types.ClassLangPkg:
		return "应用层软件包"
	default:
		return string(resultClass)
	}
}
