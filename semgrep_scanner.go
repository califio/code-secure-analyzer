package main

import (
	"analyzer/finding"
	"analyzer/logger"
	"analyzer/sarif"
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
)

type SemgrepScanner struct {
	Configs       string
	Severities    string
	ProEngine     bool
	ExcludedPaths string
	Verbose       bool
	Output        string
	ProjectPath   string
}

func (scanner *SemgrepScanner) Scan() ([]finding.Finding, error) {
	args := scanner.args()
	cmd := exec.Command("semgrep", args...)
	logger.Info(cmd.String())
	cmd.Env = os.Environ()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	go printStdout(stdout)
	go printStdout(stderr)
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}
	reader, _ := os.Open(scanner.Output)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var rep sarif.Sarif
	err = json.Unmarshal(data, &rep)
	if err != nil {
		return nil, err
	}
	return sarif.ToFindings(&rep), nil
}

func (scanner *SemgrepScanner) args() []string {
	args := []string{
		"scan",
		"--no-rewrite-rule-ids",
		"--dataflow-traces",
		"--disable-version-check",
		"--sarif",
		"--output", scanner.Output,
	}
	if strings.TrimSpace(scanner.ExcludedPaths) != "" {
		excludes := strings.Split(scanner.ExcludedPaths, ",")
		for _, exclude := range excludes {
			args = append(args, "--exclude", strings.TrimSpace(exclude))
		}
	}
	if strings.TrimSpace(scanner.ExcludedPaths) != "" {
		severities := strings.Split(scanner.Severities, ",")
		for _, severity := range severities {
			if severity == "INFO" || severity == "WARNING" || severity == "ERROR" {
				args = append(args, "--severity", strings.TrimSpace(severity))
			}
		}
	}

	if scanner.ProEngine {
		args = append(args, "--pro")
	}

	if strings.TrimSpace(scanner.Configs) != "" {
		configs := strings.Split(scanner.Configs, ",")
		for _, config := range configs {
			args = append(args, "--config", strings.TrimSpace(config))
		}
	}
	if scanner.Verbose {
		args = append(args, "--verbose")
	}
	if scanner.ProjectPath == "" {
		scanner.ProjectPath = "."
	}
	args = append(args, scanner.ProjectPath)
	return args
}

func printStdout(stdout io.ReadCloser) {
	reader := bufio.NewReader(stdout)
	line, _, err := reader.ReadLine()
	for {
		if err != nil || line == nil {
			break
		}
		logger.Println(string(line))
		line, _, err = reader.ReadLine()
	}
}