package test

import (
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

func TestCommentOnPR(t *testing.T) {
	_ = godotenv.Load()
	env, _ := git.NewGitHub()
	env.CreateMRDiscussion(git.MRDiscussionOption{
		Title:     "Test MR Discussion",
		Body:      "Test Comment",
		Path:      "README.md",
		StartLine: 3,
		EndLine:   3,
	})

}
