package test

import (
	"os"
	"testing"
	"github.com/califio/code-secure-analyzer/git"
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
