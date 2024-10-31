package main

import (
	"analyzer/logger"
	"analyzer/scm"
	"github.com/urfave/cli/v2"
	"os"
)

const (
	flagExclude    = "exclude"
	flagProMode    = "pro"
	flagConfigs    = "config"
	flagSeverities = "severity"
	flagVerbose    = "verbose"
	flagOutput     = "output"
	AnalyzeCommand = "run"
)

func analyzeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    flagProMode,
			Usage:   "Inter-file analysis and Pro languages. Requires Semgrep Pro Engine",
			EnvVars: []string{"SEMGREP_PRO"},
			Value:   true,
		},
		&cli.StringFlag{
			Name:    flagExclude,
			Usage:   "Skip any file or directory that matches this pattern",
			EnvVars: []string{"SEMGREP_EXCLUDED_PATHS"},
			Value:   "",
		},
		&cli.StringFlag{
			Name:    flagSeverities,
			Usage:   "Skip any file or directory that matches this pattern",
			EnvVars: []string{"SEMGREP_SEVERITY"},
			Value:   "",
		},
		&cli.StringFlag{
			Name:    flagConfigs,
			Usage:   "YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Semgrep registry entry name.",
			EnvVars: []string{"SEMGREP_RULES"},
			Value:   "",
		},
		&cli.BoolFlag{
			Name:    flagVerbose,
			Usage:   "Show verbose",
			EnvVars: []string{"SEMGREP_DEBUG", "SEMGREP_VERBOSE"},
			Value:   false,
		},
		&cli.StringFlag{
			Name:    flagOutput,
			Usage:   "Sarif output file",
			Value:   "semgrep.sarif",
			EnvVars: []string{"SEMGREP_OUTPUT"},
		},
	}
}

func analyzeCommand() *cli.Command {
	flags := analyzeFlags()
	return &cli.Command{
		Name:  AnalyzeCommand,
		Usage: "semgrep-ci",
		Flags: flags,
		Action: func(context *cli.Context) error {
			// register handler
			RegisterHandler(&DefaultHandler{})
			// register scanner
			scanner := &SemgrepScanner{
				Configs:       context.String(flagConfigs),
				Severities:    context.String(flagSeverities),
				ProEngine:     context.Bool(flagProMode),
				ExcludedPaths: context.String(flagExclude),
				Verbose:       context.Bool(flagVerbose),
				Output:        context.String(flagOutput),
			}
			RegisterScanner(scanner)
			// register source manager (GitLab, GitHub)
			// gitlab
			gitlab, err := scm.NewGitlab()
			if err != nil {
				logger.Error(err.Error())
			} else {
				RegisterSourceManager(gitlab)
			}
			// other source manager
			//
			findings := analyzer.Scan()
			analyzer.HandleFindings(findings)
			return nil
		},
	}
}

func main() {
	app := &cli.App{
		Name:  "analyzer",
		Usage: "Semgrep analyzer",
		Commands: []*cli.Command{
			analyzeCommand(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		logger.Fatal(err.Error())
	}
}
