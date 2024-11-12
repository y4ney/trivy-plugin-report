package main

import (
	"encoding/json"
	"flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/y4ney/trivy-plugin-report/internal/excel"
	"github.com/y4ney/trivy-plugin-report/internal/markdown"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		log.Fatal("failed to export excel file:%v", err)
	}
}

func run() error {
	// First we read Stdin to avoid Trivy freezing if we get an error
	var report types.Report
	log.InitLogger(false, false)
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		return err
	}
	log.Infof("success to get report for %s", report.ArtifactName)

	excelFile := flag.String(
		"excel-file",
		"",
		"specify the name of excel file",
	)
	beautify := flag.Bool(
		"beautify",
		false,
		"beautify the sheet(fill the background color of the cell according to the severity of the vulnerability.)",
	)
	markdownFile := flag.String(
		"markdown-file",
		"",
		"specify the name of markdown file",
	)
	flag.Parse()

	if *excelFile != "" {
		if !strings.HasSuffix(*excelFile, ".xlsx") {
			log.Fatal("just support .xlsx file")
		}
		if err := excel.Export(&report, *excelFile, *beautify); err != nil {
			return err
		}
		log.Infof("success to export %s for %s", *excelFile, report.ArtifactName)
	}
	if *markdownFile != "" {
		if !strings.HasSuffix(*markdownFile, ".md") {
			log.Fatal("just support .md file")
		}
		if err := markdown.Export(&report, *markdownFile); err != nil {
			return err
		}
		log.Infof("success to export %s for %s", *markdownFile, report.ArtifactName)
	}

	return nil
}
