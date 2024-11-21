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

// SASTAnalyzer start
type SASTAnalyzer struct {
	Analyzer
	scanner SASTScanner
}

func (analyzer *SASTAnalyzer) RegisterScanner(scanner SASTScanner) {
	analyzer.scanner = scanner
}

func (analyzer *SASTAnalyzer) Run() {
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
	analyzer.handler.InitScan(analyzer.sourceManager, analyzer.scanner.Name(), Sast)
	result, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	analyzer.handler.HandleSAST(analyzer.sourceManager, result)
	analyzer.handler.CompletedScan()
}

func NewSASTAnalyzer() *SASTAnalyzer {
	analyzer := &SASTAnalyzer{
		Analyzer: Analyzer{
			handler: GetHandler(),
		},
		scanner: nil,
	}
	analyzer.initDefaultSourceManager()
	return analyzer
}

// DependencyAnalyzer start
type DependencyAnalyzer struct {
	Analyzer
	scanner DependencyScanner
}

func (analyzer *DependencyAnalyzer) RegisterScanner(scanner DependencyScanner) {
	analyzer.scanner = scanner
}

func (analyzer *DependencyAnalyzer) Run() {
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
	analyzer.handler.InitScan(analyzer.sourceManager, analyzer.scanner.Name(), Dependency)
	result, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	analyzer.handler.HandleDependency(analyzer.sourceManager, result)
	analyzer.handler.CompletedScan()
}

func NewDependencyAnalyzer() *DependencyAnalyzer {
	analyzer := &DependencyAnalyzer{
		Analyzer: Analyzer{
			handler: GetHandler(),
		},
		scanner: nil,
	}
	analyzer.initDefaultSourceManager()
	return analyzer
}
