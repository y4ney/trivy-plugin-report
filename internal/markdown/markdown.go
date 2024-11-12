package markdown

import (
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/y4ney/trivy-plugin-report/internal/utils"
	"os"
	"strconv"
	"strings"
)

func Export(report *types.Report, fileName string) (err error) {
	md := utils.NewMarkdown(utils.WithName(fileName))

	md.SetH1("1. 概述")
	md = AddArtifactInfo(report, md)
	md = AddImageConf(report.Metadata.ImageConfig, md)
	md = AddVulnOverview(report, md)

	md.SetH1("2. 扫描结果")
	md = AddScanResult(report, md)

	return os.WriteFile(md.Name, []byte(md.Data), os.ModePerm)
}

func AddArtifactInfo(report *types.Report, md *utils.Markdown) *utils.Markdown {
	var (
		artifactType = utils.SetArtifactType(report.ArtifactType)
		osInfo       = fmt.Sprintf("%s %s", report.Metadata.OS.Family, report.Metadata.OS.Name)
		scanTime     = utils.FormatTime(&report.CreatedAt, true)
	)
	md.SetH2("1.1 制品信息")
	md.SetText(fmt.Sprintf("%s %s 基于 %s 操作系统构建，适用于 %s 架构，并在 %s 的安全扫描中发现了潜在的安全问题。",
		artifactType, report.ArtifactName, osInfo, report.Metadata.ImageConfig.Architecture, scanTime))
	artifactInfo := [][]string{
		{"制品名称", report.ArtifactName},
		{"创建时间", utils.FormatTime(&report.Metadata.ImageConfig.Created.Time, true)},
		{"架构", report.Metadata.ImageConfig.Architecture},
		{"操作系统", osInfo},
		{"镜像 ID", report.Metadata.ImageID},
		{"仓库标签", strings.Join(report.Metadata.RepoTags, "<br/>")},
		{"Docker 版本", report.Metadata.ImageConfig.DockerVersion},
		{"扫描时间", scanTime},
	}
	if report.Metadata.ImageConfig.Container != "" {
		artifactInfo = append(artifactInfo, []string{"容器", report.Metadata.ImageConfig.Container})
	}
	md.SetTable([]string{"制品类型", artifactType}, artifactInfo)
	return md
}
func AddVulnOverview(report *types.Report, md *utils.Markdown) *utils.Markdown {
	var (
		Severities = make(map[string]map[string]int)
		Vulns      = make(map[string]int)
		Pkgs       = make(map[string]int)
		FixedVulns = make(map[string]int)
		target     string
		vulnName   string
		fixedCount int
		vulnCount  int
	)
	for _, result := range report.Results {
		if result.Class != types.ClassOSPkg && result.Class != types.ClassLangPkg {
			continue
		}
		if result.Class == types.ClassOSPkg {
			target = fmt.Sprintf("系统层组件漏洞：%s", result.Target)
		} else {
			target = fmt.Sprintf("应用层组件漏洞：%s", result.Target)
		}
		Severities[target] = make(map[string]int)
		for _, vuln := range result.Vulnerabilities {
			if vuln.Title == "" {
				vulnName = vuln.VulnerabilityID
			} else {
				vulnName = fmt.Sprintf("%s : %s", vuln.VulnerabilityID, vuln.Title)
			}
			Severities[target][vuln.Severity]++
			Vulns[vulnName]++
			Pkgs[vuln.PkgName]++
			vulnCount++
			if vuln.FixedVersion != "" {
				fixedCount++
				FixedVulns[vulnName]++
			}
		}
	}

	md.SetH2("1.3 漏洞概览")
	md = countSeverity(md, Severities)
	md = countFixedVuln(md, FixedVulns, fixedCount, vulnCount)
	md = countPkgs(md, Pkgs)
	return countVulns(md, Vulns)
}
func AddImageConf(ImageConfig v1.ConfigFile, md *utils.Markdown) *utils.Markdown {
	var (
		histories [][]string
		confs     [][]string
	)

	for _, history := range ImageConfig.History {
		histories = append(histories, []string{history.Created.Format("2006-01-02 15:04:05"), history.CreatedBy})
	}
	for _, cmd := range ImageConfig.Config.Cmd {
		confs = append(confs, []string{"执行命令", cmd})
	}
	for _, env := range ImageConfig.Config.Env {
		confs = append(confs, []string{"环境变量", env})
	}
	md.SetH2("1.2 镜像配置")
	md.SetText("镜像创建历史记录如下所示，请手动检查是否有可疑的执行命令，例如下载恶意文件等。")
	md.SetTable([]string{"创建时间", "历史记录"}, histories)
	md.SetText("镜像配置信息如下所示，请手动检查是否有可疑的执行命令和暴露的 secret，例如执行恶意命令和应用程序密钥等。")
	md.SetTable([]string{"配置类型", "内容"}, confs)
	return md
}
func AddScanResult(report *types.Report, md *utils.Markdown) *utils.Markdown {
	var pkgInfo, vulnInfo [][]string
	for i, result := range report.Results {
		md.SetH2(fmt.Sprintf("2.%v %s", i+1, result.Target))
		md.SetTable([]string{"扫描目标", result.Target}, [][]string{
			{"软件包类型", utils.SetResultClass(result.Class)},
			{"目标类型", string(result.Type)}})

		for j, vulnerability := range result.Vulnerabilities {
			if vulnerability.Title == "" {
				md.SetH3(fmt.Sprintf("2.%v.%v %s", i+1, j+1, vulnerability.VulnerabilityID))
			} else {
				md.SetH3(fmt.Sprintf("2.%v.%v %s:%s", i+1, j+1, vulnerability.VulnerabilityID, vulnerability.Title))
			}

			// 软件包信息
			md.SetH4(fmt.Sprintf("2.%v.%v.1 软件包信息", i+1, j+1))
			pkgInfo = [][]string{{"软件包名称", vulnerability.PkgName}, {"安装版本", vulnerability.InstalledVersion}}
			if vulnerability.PkgID != "" {
				pkgInfo = append(pkgInfo, []string{"软件包 ID", vulnerability.PkgID})
			}
			if vulnerability.FixedVersion != "" {
				pkgInfo = append(pkgInfo, []string{"修复版本", vulnerability.FixedVersion})
			}
			md.SetTable([]string{"软件包 URL", vulnerability.PkgIdentifier.PURL.String()}, pkgInfo)

			// 漏洞信息
			md.SetH4(fmt.Sprintf("2.%v.%v.2 漏洞信息", i+1, j+1))
			vulnInfo = [][]string{
				{"威胁等级", vulnerability.Severity},
				{"状态", vulnerability.Status.String()},
			}
			if vulnerability.Title != "" {
				vulnInfo = append(vulnInfo, []string{"漏洞标题", vulnerability.Title})
			}
			if vulnerability.SeveritySource != "" {
				vulnInfo = append(vulnInfo, []string{"威胁等级来源", string(vulnerability.SeveritySource)})
			}
			if vulnerability.VendorIDs != nil {
				vulnInfo = append(vulnInfo, []string{"供应商的漏洞编号", strings.Join(vulnerability.VendorIDs, "<br/>")})
			}
			if vulnerability.PublishedDate != nil {
				vulnInfo = append(vulnInfo, []string{"披露时间", vulnerability.PublishedDate.Format("2006-01-02 15:04:05")})
			}
			if vulnerability.LastModifiedDate != nil {
				vulnInfo = append(vulnInfo, []string{"上次修改时间", vulnerability.LastModifiedDate.Format("2006-01-02 15:04:05")})
			}

			md.SetTable([]string{"漏洞编号", vulnerability.VulnerabilityID}, vulnInfo)

			// 漏洞描述
			md.SetH4(fmt.Sprintf("2.%v.%v.3 漏洞描述", i+1, j+1))
			md.SetText(vulnerability.Description)

			// 相关链接
			md.SetH4(fmt.Sprintf("2.%v.%v.4 相关链接", i+1, j+1))
			md.SetUl(append([]string{vulnerability.PrimaryURL, vulnerability.DataSource.URL}, vulnerability.References...))
		}
	}
	return md
}

func countSeverity(md *utils.Markdown, SeverityCount map[string]map[string]int) *utils.Markdown {
	var (
		Severities                                [][]string
		critical, high, medium, low, unknown, all int
	)

	for target, severities := range SeverityCount {
		Severities = append(Severities, []string{
			target,
			strconv.Itoa(severities["CRITICAL"]),
			strconv.Itoa(severities["HIGH"]),
			strconv.Itoa(severities["MEDIUM"]),
			strconv.Itoa(severities["LOW"]),
			strconv.Itoa(severities["UNKNOWN"]),
			strconv.Itoa(severities["CRITICAL"] + severities["HIGH"] + severities["MEDIUM"] +
				severities["LOW"] + severities["UNKNOWN"]),
		})
		critical += severities["CRITICAL"]
		high += severities["HIGH"]
		medium += severities["MEDIUM"]
		low += severities["LOW"]
		unknown += severities["UNKNOWN"]
	}
	all = critical + high + medium + low + unknown
	Severities = append(Severities, []string{
		"漏洞总数", strconv.Itoa(critical), strconv.Itoa(high), strconv.Itoa(medium),
		strconv.Itoa(low), strconv.Itoa(unknown), strconv.Itoa(all),
	})
	md.SetText(fmt.Sprintf("本次共扫描出 %v 个漏洞，超危漏洞有 %v 个，占比 %.2f%% ；高危漏洞有 %v 个，占比 %.2f%% 。",
		all, critical, float64(critical)/float64(all)*100, high, float64(high)/float64(all)*100))
	md.SetTable([]string{"", "超危", "高危", "中危", "低危", "未知", "总计"}, Severities)
	return md
}
func countFixedVuln(md *utils.Markdown, FixedVuln map[string]int, fixedCount int, vulnCount int) *utils.Markdown {
	md.SetText(fmt.Sprintf("其中可修复的漏洞有 %v 个，占比 %.2f%% 。", fixedCount, float64(fixedCount)/float64(vulnCount)*100))
	md.SetTable([]string{"可修复漏洞", "漏洞数量"}, utils.Sort(FixedVuln))
	return md
}
func countVulns(md *utils.Markdown, vulns map[string]int) *utils.Markdown {
	md.SetText(fmt.Sprintf("全量漏洞如下所示，漏洞详情请看第二部分的扫描结果。"))
	md.SetTable([]string{"漏洞名称", "漏洞数量"}, utils.Sort(vulns))
	return md
}
func countPkgs(md *utils.Markdown, pkgs map[string]int) *utils.Markdown {
	md.SetText(fmt.Sprintf("包含漏洞的软件包如下所示。"))
	md.SetTable([]string{"软件包名称", "包含的漏洞数量"}, utils.Sort(pkgs))
	return md
}
