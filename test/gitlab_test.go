package test

import (
	"gitlab.com/code-secure/analyzer/finding"
	"gitlab.com/code-secure/analyzer/git"
	"testing"
)

func TestCommentSASTMergeRequest(t *testing.T) {
	sourceManager, err := git.NewGitlab()
	if err != nil {
		t.Fatal(err)
	}
	mergeRequest := git.MergeRequest{
		SourceBranch:      "feature/cowsay-api",
		TargetBranch:      "main",
		TargetBranchHash:  "test",
		SourceBranchHash:  "test",
		MergeRequestID:    "24",
		MergeRequestTitle: "Feature cowsay api",
	}
	err = sourceManager.CommentSASTFindingOnMergeRequest([]finding.SASTFinding{
		finding.SASTFinding{
			RuleID:         "",
			Identity:       "",
			Name:           "Java Lang Security Audit Command Injection Process Builder at src/main/java/com/scalesec/vulnado/Cowsay.java:11",
			Description:    "",
			Category:       "",
			Recommendation: "",
			Severity:       "",
			Location: &finding.Location{
				Path:        "src/main/java/com/scalesec/vulnado/Cowsay.java",
				Snippet:     "processBuilder.command(\\\"bash\\\", \\\"-c\\\", cmd);",
				StartLine:   11,
				EndLine:     11,
				StartColumn: 42,
				EndColumn:   45,
			},
			FindingFlow: []finding.Location{
				finding.Location{
					Path:        "src/main/java/com/scalesec/vulnado/CowController.java",
					Snippet:     "input",
					StartLine:   12,
					EndLine:     12,
					StartColumn: 72,
					EndColumn:   77,
				},
				finding.Location{
					Path:        "src/main/java/com/scalesec/vulnado/CowController.java",
					Snippet:     "Cowsay.run",
					StartLine:   13,
					EndLine:     13,
					StartColumn: 16,
					EndColumn:   26,
				},
				finding.Location{
					Path:        "src/main/java/com/scalesec/vulnado/Cowsay.java",
					Snippet:     "processBuilder.command(\\\"bash\\\", \\\"-c\\\", cmd);",
					StartLine:   11,
					EndLine:     11,
					StartColumn: 42,
					EndColumn:   45,
				},
			},
		},
	}, &mergeRequest)
	if err != nil {
		t.Fatal(err)
	}

}
