package main

import (
	"analyzer/git"
	"analyzer/handler"
	"analyzer/logger"
)

type Analyzer[T any] struct {
	scanner        Scanner[T]
	handler        handler.Handler[T]
	sourceManager  git.SourceManager
	sourceManagers []git.SourceManager
	scanId         string
}

func NewAnalyzer[T any]() *Analyzer[T] {
	// init default source manager
	var sourceManagers []git.SourceManager
	// gitlab
	gitlab, err := git.NewGitlab()
	if err != nil {
		logger.Error(err.Error())
	} else {
		sourceManagers = append(sourceManagers, gitlab)
	}
	// todo: github
	// todo: support other source managers
	return &Analyzer[T]{
		sourceManagers: sourceManagers,
	}
}

func (analyzer *Analyzer[T]) RegisterScanner(scanner Scanner[T]) {
	analyzer.scanner = scanner
}

func (analyzer *Analyzer[T]) RegisterSourceManager(sourceManager git.SourceManager) {
	analyzer.sourceManagers = append(analyzer.sourceManagers, sourceManager)
	analyzer.sourceManager = sourceManager
}

func (analyzer *Analyzer[T]) RegisterHandler(handler handler.Handler[T]) {
	analyzer.handler = handler
}

func (analyzer *Analyzer[T]) Scan() []T {
	if analyzer.scanner == nil {
		logger.Fatal("there is no scanner")
	}
	if analyzer.handler == nil {
		logger.Fatal("there is no handler")
	}
	analyzer.initSourceManager()
	analyzer.handler.InitScan(analyzer.sourceManager, analyzer.scanner.Name())
	findings, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	return findings
}

func (analyzer *Analyzer[T]) Run() {
	findings := analyzer.Scan()
	analyzer.handler.HandleFindings(analyzer.sourceManager, findings)

}

func (analyzer *Analyzer[T]) HandleFindings(findings []T) {
	analyzer.handler.HandleFindings(analyzer.sourceManager, findings)
}

func (analyzer *Analyzer[T]) initSourceManager() {
	for _, sourceManager := range analyzer.sourceManagers {
		if sourceManager.IsActive() {
			logger.Info("Source Manager: " + sourceManager.Name())
			analyzer.sourceManager = sourceManager
			return
		}
	}
	logger.Fatal("there is no source manager")
}
