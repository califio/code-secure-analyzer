package analyzer

import (
	"github.com/califio/code-secure-analyzer/git"
	"github.com/califio/code-secure-analyzer/logger"
	"github.com/jedib0t/go-pretty/v6/table"
	"os"
)

type Analyzer struct {
	handler           Handler
	sourceManager     git.GitEnv
	mSourceManagers   map[string]git.GitEnv
	baselineCommitSha string
	projectPath       string
}

func (analyzer *Analyzer) RegisterSourceManager(sourceManager git.GitEnv) {
	analyzer.mSourceManagers[sourceManager.Provider()] = sourceManager
	analyzer.sourceManager = sourceManager
}

func (analyzer *Analyzer) RegisterHandler(handler Handler) {
	analyzer.handler = handler
}

func (analyzer *Analyzer) initDefaultSourceManager() {
	analyzer.mSourceManagers = make(map[string]git.GitEnv)
	gitlab, err := git.NewGitLab()
	if err != nil {
		logger.Error(err.Error())
	} else {
		analyzer.mSourceManagers[gitlab.Provider()] = gitlab
	}
}

func (analyzer *Analyzer) detectSourceManager() {
	for _, sourceManager := range analyzer.mSourceManagers {
		if sourceManager.IsActive() {
			analyzer.sourceManager = sourceManager
			return
		}
	}
	logger.Fatal("there is no source manager")
}

// SastAnalyzer start
type SastAnalyzer struct {
	Analyzer
	scanner SastScanner
}

type SastAnalyzerOption struct {
	ProjectPath string
	Scanner     SastScanner
}

func NewSastAnalyzer(option SastAnalyzerOption) *SastAnalyzer {
	analyzer := &SastAnalyzer{
		Analyzer: Analyzer{
			handler:     GetHandler(),
			projectPath: option.ProjectPath,
		},
		scanner: option.Scanner,
	}
	analyzer.initDefaultSourceManager()
	return analyzer
}

func (analyzer *SastAnalyzer) RegisterScanner(scanner SastScanner) {
	analyzer.scanner = scanner
}

func (analyzer *SastAnalyzer) Run() {
	if IsDir(analyzer.projectPath) == false {
		logger.Fatal(analyzer.projectPath + " is not a directory")
	}
	if analyzer.scanner == nil {
		logger.Fatal("no scanner")
	}
	if analyzer.handler == nil {
		analyzer.handler = GetHandler()
		if analyzer.handler == nil {
			logger.Fatal("no handler")
		}
	}
	if analyzer.mSourceManagers == nil {
		analyzer.initDefaultSourceManager()
	}
	analyzer.detectSourceManager()
	scanInfo, err := analyzer.handler.OnStart(analyzer.sourceManager, analyzer.scanner.Name(), analyzer.scanner.Type())
	if err != nil {
		logger.Fatal(err.Error())
	}
	//
	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetStyle(table.StyleLight)
	tbl.Style().Options.SeparateRows = true
	tbl.AppendRow(table.Row{"Provider", analyzer.sourceManager.Provider()})
	tbl.AppendRow(table.Row{"Repo", analyzer.sourceManager.ProjectURL()})
	if analyzer.sourceManager.CommitBranch() != "" {
		tbl.AppendRow(table.Row{"Branch", analyzer.sourceManager.CommitBranch()})
	}
	tbl.AppendRow(table.Row{"Commit", analyzer.sourceManager.CommitSha()})
	scanStrategy := AllFiles
	var changedFiles []ChangedFile
	if git.IsGitRepo(analyzer.projectPath) {
		// merge request
		if analyzer.sourceManager.MergeRequestID() != "" && analyzer.sourceManager.TargetBranchSha() != "" {
			analyzer.baselineCommitSha = analyzer.sourceManager.TargetBranchSha()
			tbl.AppendRow(table.Row{"Merge Request", analyzer.sourceManager.MergeRequestID()})
		} else if analyzer.sourceManager.CommitSha() != "" && scanInfo.LastCommitSha != "" {
			analyzer.baselineCommitSha = scanInfo.LastCommitSha
		}
		if analyzer.baselineCommitSha != "" && analyzer.baselineCommitSha != analyzer.sourceManager.CommitSha() {
			objectChange, err := git.DiffCommit(analyzer.projectPath, analyzer.sourceManager.CommitSha(), analyzer.baselineCommitSha)
			if err != nil {
				logger.Error(err.Error())
			}
			changedFiles = FromObjectChanges(objectChange)
			scanStrategy = ChangedFileOnly
		}
	}
	tbl.AppendRow(table.Row{"Scanner", analyzer.scanner.Name()})
	tbl.AppendRow(table.Row{"Scan Strategy", scanStrategy.String()})
	if scanInfo.ScanId != "" {
		tbl.AppendRow(table.Row{"Scan ID", scanInfo.ScanId})
	}
	if scanInfo.LastCommitSha != "" {
		tbl.AppendRow(table.Row{"Last Scan Commit", scanInfo.LastCommitSha})
	}
	if scanInfo.ScanUrl != "" {
		tbl.AppendRow(table.Row{"Scan URL", scanInfo.ScanUrl})
	}
	tbl.Render()
	//
	result, err := analyzer.scanner.Scan(ScanOption{
		ChangedFiles:      changedFiles,
		ScanStrategy:      scanStrategy,
		BaseLineCommitSha: analyzer.baselineCommitSha,
	})
	if err != nil {
		analyzer.handler.OnError(err)
		logger.Fatal(err.Error())
	}
	if result != nil {
		analyzer.handler.HandleSastFindings(HandleSastFindingPros{
			Result:        *result,
			Strategy:      scanStrategy,
			ChangedFiles:  changedFiles,
			SourceManager: analyzer.sourceManager,
		})
	} else {
		logger.Error("Finding result nil")
	}
	analyzer.handler.OnCompleted()
}

// ScaAnalyzer start
type ScaAnalyzer struct {
	Analyzer
	scanner ScaScanner
}

func (analyzer *ScaAnalyzer) RegisterScanner(scanner ScaScanner) {
	analyzer.scanner = scanner
}

func (analyzer *ScaAnalyzer) Run() {
	if analyzer.scanner == nil {
		logger.Fatal("no scanner")
	}
	if analyzer.handler == nil {
		analyzer.handler = GetHandler()
		if analyzer.handler == nil {
			logger.Fatal("no handler")
		}
	}
	if analyzer.mSourceManagers == nil {
		analyzer.initDefaultSourceManager()
	}
	analyzer.detectSourceManager()
	_, err := analyzer.handler.OnStart(analyzer.sourceManager, analyzer.scanner.Name(), analyzer.scanner.Type())
	if err != nil {
		logger.Fatal(err.Error())
	}
	result, err := analyzer.scanner.Scan()
	if err != nil {
		logger.Fatal(err.Error())
	}
	if result != nil {
		analyzer.handler.HandleSCA(analyzer.sourceManager, *result)
	} else {
		logger.Error("SCA result nil")
	}
	analyzer.handler.OnCompleted()
}

func NewScaAnalyzer() *ScaAnalyzer {
	analyzer := &ScaAnalyzer{
		Analyzer: Analyzer{
			handler: GetHandler(),
		},
		scanner: nil,
	}
	analyzer.initDefaultSourceManager()
	return analyzer
}
