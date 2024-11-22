package test

import (
	"gitlab.com/code-secure/analyzer"
	"gitlab.com/code-secure/analyzer/logger"
	"testing"
)

var client, _ = analyzer.NewClient("http://localhost:5272", "962ba2f962eb4e4abb6679d3bae259906da2d320dc924cb29ed12a83a6fdfdad")

var SastResult = analyzer.FindingResult{
	Findings: []analyzer.Finding{
		analyzer.Finding{
			RuleID:         "rule-test-02",
			Identity:       "rule-test-02",
			Name:           "Finding Test 02",
			Description:    "Finding Description 02",
			Recommendation: "",
			Severity:       analyzer.SeverityCritical,
			Location: &analyzer.FindingLocation{
				Path:      "src/test.java",
				Snippet:   "input",
				StartLine: analyzer.Ptr(4),
				EndLine:   analyzer.Ptr(4),
			},
			Metadata: &analyzer.FindingMetadata{
				FindingFlow: []analyzer.FindingLocation{
					analyzer.FindingLocation{
						Path:      "src/test.java",
						Snippet:   "sink",
						StartLine: analyzer.Ptr(4),
						EndLine:   analyzer.Ptr(4),
					},
					analyzer.FindingLocation{
						Path:      "src/test.java",
						Snippet:   "sink",
						StartLine: analyzer.Ptr(8),
						EndLine:   analyzer.Ptr(8),
					},
				},
			},
		},
	},
}

var ScaResult = analyzer.SCAResult{
	Packages: []analyzer.Package{
		analyzer.Package{
			PkgId:    "01967d44-26a5-4eee-a1ac-46b30f5a2594",
			Group:    "org.springframework",
			Name:     "spring-webmvc",
			Version:  "4.1.6.RELEASE",
			Type:     "pom",
			Location: analyzer.Ptr("pom.xml"),
		},
		analyzer.Package{
			PkgId:   "11c90fc0-5d2b-410d-8873-188674b75866",
			Group:   "org.springframework",
			Name:    "spring-core",
			Version: "4.1.6.RELEASE",
			Type:    "pom",
		},
		analyzer.Package{
			PkgId:   "56434cd1-8ab7-4cbc-9f36-d981b5e1c7f3",
			Group:   "org.springframework",
			Name:    "spring-beans",
			Version: "4.1.6.RELEASE",
			Type:    "pom",
		},
	},
	PackageDependencies: []analyzer.PackageDependency{
		analyzer.PackageDependency{
			PkgId: "01967d44-26a5-4eee-a1ac-46b30f5a2594",
			Dependencies: []string{
				"11c90fc0-5d2b-410d-8873-188674b75866",
				"56434cd1-8ab7-4cbc-9f36-d981b5e1c7f3",
			},
		},
	},
	Vulnerabilities: []analyzer.Vulnerability{
		analyzer.Vulnerability{
			Identity:     "CVE-2022-22965",
			Name:         "CVE-2022-22965",
			Description:  "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
			FixedVersion: "4.1.19",
			Severity:     analyzer.SeverityHigh,
			PkgId:        "01967d44-26a5-4eee-a1ac-46b30f5a2594",
			PkgName:      "org.springframework.spring-webmvc",
			Metadata: &analyzer.FindingMetadata{
				Cvss: analyzer.Ptr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			},
		},
	},
}

func TestInitScan(t *testing.T) {
	isDefault := false
	scan, err := client.InitScan(&analyzer.CiScanRequest{
		Source:         "GitLab",
		RepoId:         "50471840",
		RepoUrl:        "https://gitlab.com/0xduo/vulnado",
		RepoName:       "0xduo/vulnado",
		GitAction:      analyzer.GitCommitBranch,
		ScanTitle:      "Test Commit",
		CommitBranch:   "main",
		CommitHash:     "891832b2fdecb72c444af1a6676eba6eb40435ab",
		TargetBranch:   "",
		MergeRequestId: "",
		Scanner:        "semgrep",
		Type:           analyzer.ScannerTypeSast,
		JobUrl:         "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355",
		IsDefault:      analyzer.Ptr(isDefault),
	})
	if err != nil {
		logger.Error(err.Error())
		return
	}
	logger.Info(scan.ScanId)
}
func TestScanSAST(t *testing.T) {
	scan, err := client.InitScan(&analyzer.CiScanRequest{
		Source:         "GitLab",
		RepoId:         "50471840",
		RepoUrl:        "https://gitlab.com/0xduo/vulnado",
		RepoName:       "0xduo/vulnado",
		GitAction:      analyzer.GitCommitBranch,
		ScanTitle:      "Test Commit",
		CommitBranch:   "main",
		CommitHash:     "891832b2fdecb72c444af1a6676eba6eb40435ab",
		TargetBranch:   "",
		MergeRequestId: "",
		Scanner:        "semgrep",
		Type:           analyzer.ScannerTypeSast,
		JobUrl:         "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355",
		IsDefault:      analyzer.Ptr(true),
	})
	if err != nil {
		t.Fatal(err.Error())
	}
	if scan == nil || scan.ScanId == "" {
		t.Fatal()
	}

	_, err = client.UploadFinding(analyzer.UploadFindingRequest{
		ScanId:   scan.ScanId,
		Findings: SastResult.Findings,
	})
	if err != nil {
		t.Fatal(err.Error())
	}
	err = client.UpdateScan(scan.ScanId, analyzer.UpdateCIScanRequest{
		Status:      analyzer.Ptr(analyzer.StatusCompleted),
		Description: nil,
	})
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestScanDependency(t *testing.T) {
	scan, err := client.InitScan(&analyzer.CiScanRequest{
		Source:         "GitLab",
		RepoId:         "50471840",
		RepoUrl:        "https://gitlab.com/0xduo/vulnado",
		RepoName:       "0xduo/vulnado",
		GitAction:      analyzer.GitCommitBranch,
		ScanTitle:      "Test Commit",
		CommitBranch:   "main",
		CommitHash:     "891832b2fdecb72c444af1a6676eba6eb40435ab",
		TargetBranch:   "",
		MergeRequestId: "",
		Scanner:        "trivy",
		Type:           analyzer.ScannerTypeDependency,
		JobUrl:         "https://gitlab.com/0xduo/vulnado/-/jobs/8241092355",
		IsDefault:      analyzer.Ptr(true),
	})
	if err != nil {
		t.Fatal(err.Error())
	}
	if scan == nil || scan.ScanId == "" {
		t.Fatal()
	}

	_, err = client.UploadDependency(analyzer.UploadDependencyRequest{
		ScanId:              scan.ScanId,
		Packages:            ScaResult.Packages,
		PackageDependencies: ScaResult.PackageDependencies,
		Vulnerabilities:     ScaResult.Vulnerabilities,
	})
	if err != nil {
		t.Fatal(err.Error())
	}
	err = client.UpdateScan(scan.ScanId, analyzer.UpdateCIScanRequest{
		Status:      analyzer.Ptr(analyzer.StatusCompleted),
		Description: nil,
	})
	if err != nil {
		t.Fatal(err.Error())
	}
}
