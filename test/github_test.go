package test

import (
	"fmt"
	"github.com/califio/code-secure-analyzer/git"
	"github.com/joho/godotenv"
	"os"
	"testing"
)

func TestProviderAndProjectInfo(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "califio/code-secure-analyzer")
	env, _ := git.NewGitHub()
	if env.Provider() != "GitHub" {
		t.Errorf("Provider should be GitHub")
	}
	if env.ProjectID() != "califio/code-secure-analyzer" {
		t.Errorf("ProjectID mismatch")
	}
	if env.ProjectName() != "code-secure-analyzer" {
		t.Errorf("ProjectName mismatch")
	}
	if env.ProjectURL() != "https://github.com/califio/code-secure-analyzer" {
		t.Errorf("ProjectURL mismatch")
	}
}

func TestGitHubEnv(t *testing.T) {
	_ = godotenv.Load()
	os.Setenv("GITHUB_EVENT_PATH", "event.json")
	github, _ := git.NewGitHub()
	fmt.Println("ProjectID: " + github.ProjectID())
	fmt.Println("ProjectName: " + github.ProjectName())
	fmt.Println("ProjectURL: " + github.ProjectURL())
	fmt.Println("BlobURL: " + github.BlobURL())
	fmt.Println("DefaultBranch: " + github.DefaultBranch())
	fmt.Println("CommitTitle: " + github.CommitTitle())
	fmt.Println("CommitBranch: " + github.CommitBranch())
	fmt.Println("CommitSha: " + github.CommitSha())
	fmt.Println("MergeRequestID: " + github.MergeRequestID())
	fmt.Println("MergeRequestTitle: " + github.MergeRequestTitle())
	fmt.Println("TargetBranch: " + github.TargetBranch())
	fmt.Println("SourceBranch: " + github.SourceBranch())
	fmt.Println("TargetBranchSha: " + github.TargetBranchSha())
	fmt.Println("CommitTag: " + github.CommitTag())
	fmt.Println("JobURL: " + github.JobURL())
}

func TestCommentOnPR(t *testing.T) {
	_ = godotenv.Load()
	env, _ := git.NewGitHub()
	env.CreateMRDiscussion(git.MRDiscussionOption{
		Title:     "Test MR Discussion3",
		Body:      "Test Comment4",
		Path:      "src/main/java/com/scalesec/vulnado/CowController.java",
		StartLine: 16,
		EndLine:   18,
	})

}
