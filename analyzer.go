package analyzer

import (
	"gitlab.com/code-secure/analyzer/logger"
)

type Analyzer struct {
	handler         Handler
	sourceManager   SourceManager
	mSourceManagers map[string]SourceManager
}

func (analyzer *Analyzer) RegisterSourceManager(sourceManager SourceManager) {
	analyzer.mSourceManagers[sourceManager.Name()] = sourceManager
	analyzer.sourceManager = sourceManager
}

func (analyzer *Analyzer) RegisterHandler(handler Handler) {
	analyzer.handler = handler
}

func (analyzer *Analyzer) initDefaultSourceManager() {
	analyzer.mSourceManagers = make(map[string]SourceManager)
	gitlab, err := NewGitlab()
	if err != nil {
		logger.Error(err.Error())
	} else {
		analyzer.mSourceManagers[gitlab.Name()] = gitlab
	}
}

func (analyzer *Analyzer) detectSourceManager() {
	for _, sourceManager := range analyzer.mSourceManagers {
		if sourceManager.IsActive() {
			logger.Info("Source Manager: " + sourceManager.Name())
			analyzer.sourceManager = sourceManager
			return
		}
	}
	logger.Fatal("there is no source manager")
}

// FindingAnalyzer start
type FindingAnalyzer struct {
	Analyzer
	scanner FindingScanner
}

func (analyzer *FindingAnalyzer) RegisterScanner(scanner FindingScanner) {
	analyzer.scanner = scanner
}

func (analyzer *FindingAnalyzer) Run() {
	if analyzer.scanner == nil {
		logger.Fatal("there is no scanner")
	}
	if analyzer.handler == nil {
		analyzer.handler = GetHandler()
		if analyzer.handler == nil {
			logger.Fatal("there is no handler")
		}
	}
	if analyzer.mSourceManagers == nil {
		analyzer.initDefaultSourceManager()
	}
	analyzer.detectSourceManager()
	analyzer.handler.InitScan(analyzer.sourceManager, analyzer.scanner.Name(), analyzer.scanner.Type())
	result, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	if result != nil {
		analyzer.handler.HandleFindings(analyzer.sourceManager, *result)
	} else {
		logger.Error("Finding result nil")
	}
	analyzer.handler.CompletedScan()
}

func NewFindingAnalyzer() *FindingAnalyzer {
	analyzer := &FindingAnalyzer{
		Analyzer: Analyzer{
			handler: GetHandler(),
		},
		scanner: nil,
	}
	analyzer.initDefaultSourceManager()
	return analyzer
}

// SCAAnalyzer start
type SCAAnalyzer struct {
	Analyzer
	scanner SCAScanner
}

func (analyzer *SCAAnalyzer) RegisterScanner(scanner SCAScanner) {
	analyzer.scanner = scanner
}

func (analyzer *SCAAnalyzer) Run() {
	if analyzer.scanner == nil {
		logger.Fatal("there is no scanner")
	}
	if analyzer.handler == nil {
		analyzer.handler = GetHandler()
		if analyzer.handler == nil {
			logger.Fatal("there is no handler")
		}
	}
	if analyzer.mSourceManagers == nil {
		analyzer.initDefaultSourceManager()
	}
	analyzer.detectSourceManager()
	analyzer.handler.InitScan(analyzer.sourceManager, analyzer.scanner.Name(), analyzer.scanner.Type())
	result, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	if result != nil {
		analyzer.handler.HandleSCA(analyzer.sourceManager, *result)
	} else {
		logger.Error("SCA result nil")
	}
	analyzer.handler.CompletedScan()
}

func NewSCAAnalyzer() *SCAAnalyzer {
	analyzer := &SCAAnalyzer{
		Analyzer: Analyzer{
			handler: GetHandler(),
		},
		scanner: nil,
	}
	analyzer.initDefaultSourceManager()
	return analyzer
}
