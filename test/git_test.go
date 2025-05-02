package test

import (
	"github.com/califio/code-secure-analyzer/git"
	"github.com/califio/code-secure-analyzer/logger"
	"testing"
)

func TestIsGitRepo(t *testing.T) {
	if git.IsGitRepo("/tmp/foo") {
		logger.Info("Is Git Repo")
	}
}
