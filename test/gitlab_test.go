package test

import (
	"context"
	"gitlab.com/code-secure/analyzer"
	"os"
	"testing"
)

func TestCommentSASTMergeRequest(t *testing.T) {
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	os.Setenv("GITLAB_TOKEN", "")
	os.Setenv("CI_PROJECT_ID", "50471840")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado")
	os.Setenv("CI_COMMIT_SHA", "72155d553d00f913d1e9b64def483724493da19e")
	sourceManager, err := analyzer.NewGitlab()
	if err != nil {
		t.Fatal(err)
	}
	mergeRequest := analyzer.MergeRequest{
		SourceBranch:      "feature/cowsay-api",
		TargetBranch:      "main",
		TargetBranchHash:  "test",
		SourceBranchHash:  "test",
		MergeRequestID:    "24",
		MergeRequestTitle: "Feature cowsay api",
	}
	err = sourceManager.CommentFindingOnMergeRequest(context.WithValue(context.Background(), "server", "http://localhost:4200"), []analyzer.Finding{
		analyzer.Finding{
			ID:             "123",
			RuleID:         "",
			Identity:       "",
			Name:           "Java Lang Security Audit Command Injection Process Builder at src/main/java/com/scalesec/vulnado/Cowsay.java:11",
			Description:    "",
			Category:       "",
			Recommendation: "",
			Severity:       "",
			Location: &analyzer.FindingLocation{
				Path:        "src/main/java/com/scalesec/vulnado/Cowsay.java",
				Snippet:     "processBuilder.command(\\\"bash\\\", \\\"-c\\\", cmd);",
				StartLine:   analyzer.Ptr(11),
				EndLine:     analyzer.Ptr(11),
				StartColumn: analyzer.Ptr(42),
				EndColumn:   analyzer.Ptr(45),
			},
			Metadata: &analyzer.FindingMetadata{
				FindingFlow: []analyzer.FindingLocation{
					analyzer.FindingLocation{
						Path:        "src/main/java/com/scalesec/vulnado/CowController.java",
						Snippet:     "input",
						StartLine:   analyzer.Ptr(12),
						EndLine:     analyzer.Ptr(12),
						StartColumn: analyzer.Ptr(72),
						EndColumn:   analyzer.Ptr(77),
					},
					analyzer.FindingLocation{
						Path:        "src/main/java/com/scalesec/vulnado/CowController.java",
						Snippet:     "Cowsay.run",
						StartLine:   analyzer.Ptr(13),
						EndLine:     analyzer.Ptr(13),
						StartColumn: analyzer.Ptr(16),
						EndColumn:   analyzer.Ptr(26),
					},
					analyzer.FindingLocation{
						Path:        "src/main/java/com/scalesec/vulnado/Cowsay.java",
						Snippet:     "processBuilder.command(\\\"bash\\\", \\\"-c\\\", cmd);",
						StartLine:   analyzer.Ptr(11),
						EndLine:     analyzer.Ptr(11),
						StartColumn: analyzer.Ptr(42),
						EndColumn:   analyzer.Ptr(45),
					},
				},
				Cwes:       nil,
				References: nil,
				Cvss:       nil,
				CvssScore:  nil,
			},
		},
	}, &mergeRequest)
	if err != nil {
		t.Fatal(err)
	}

}
