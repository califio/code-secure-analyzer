package main

import (
	"analyzer/finding"
	"analyzer/logger"
	"analyzer/scm"
	"fmt"
	"github.com/fatih/color"
	"github.com/rodaine/table"
)

var analyzer = &Analyzer{}

func RegisterScanner(scanner Scanner) {
	analyzer.scanner = scanner
}

func RegisterHandler(handler Handler) {
	analyzer.handler = handler
}

func RegisterSourceManager(sourceManager scm.SourceManager) {
	analyzer.sourceManagers = append(analyzer.sourceManagers, sourceManager)
}

func Scan() []finding.Finding {
	return analyzer.Scan()
}

func HandleFindings(findings []finding.Finding) {
	analyzer.HandleFindings(findings)
}

type Analyzer struct {
	scanner        Scanner
	handler        Handler
	sourceManager  scm.SourceManager
	sourceManagers []scm.SourceManager
}

func (analyzer *Analyzer) Scan() []finding.Finding {
	if analyzer.scanner == nil {
		logger.Fatal("there is no scanner")
	}
	if analyzer.handler == nil {
		logger.Fatal("there is no handler")
	}
	findings, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	return findings
}

func (analyzer *Analyzer) HandleFindings(findings []finding.Finding) {
	analyzer.sourceManager = analyzer.getSourceManager()
	if analyzer.sourceManager == nil {
		logger.Warn("there is no source manager (GitLab, GitHub, vv)")
	}
	findingType := analyzer.handler.Classify(findings)
	if len(findingType.NewFindings) > 0 {
		logger.Warn(fmt.Sprintf("There are %d new findings", len(findingType.NewFindings)))
		printFindings(findingType.NewFindings)
		if analyzer.sourceManager != nil {
			// comment new findings on merge request
			if isMergeRequest, mergeRequest := analyzer.sourceManager.MergeRequest(); isMergeRequest {
				err := analyzer.sourceManager.CommentMergeRequest(findingType.NewFindings, mergeRequest)
				if err != nil {
					logger.Error("Comment on merge request error")
					logger.Error(err.Error())
				}
			}
		}
	}

	if len(findingType.FixedFindings) > 0 {
		logger.Info(fmt.Sprintf("There are %d findings that have been fixed", len(findingType.FixedFindings)))
		printFindings(findingType.FixedFindings)
	}

	if len(findingType.OldFindings) > 0 {
		logger.Info(fmt.Sprintf("There are still %d findings not yet fixed", len(findingType.FixedFindings)))
		printFindings(findingType.OldFindings)
	}
}

func (analyzer *Analyzer) getSourceManager() scm.SourceManager {
	for _, sourceManager := range analyzer.sourceManagers {
		if sourceManager.IsActive() {
			logger.Info("Source Manager: " + sourceManager.Name())
			return sourceManager
		}
	}
	return nil
}

func printFindings(findings []finding.Finding) {
	tbl := table.New("ID", "Name", "Severity", "Location")

	tbl.WithHeaderFormatter(color.New(color.FgGreen, color.Underline).SprintfFunc()).
		WithFirstColumnFormatter(color.New(color.FgYellow).SprintfFunc())
	for index, issue := range findings {
		tbl.AddRow(index+1, issue.Name, issue.Severity, issue.Location.String())
	}
	tbl.Print()
}
