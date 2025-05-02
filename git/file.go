package git

import (
	"errors"
	"github.com/califio/code-secure-analyzer/logger"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func IsGitRepo(projectPath string) bool {
	_, err := git.PlainOpenWithOptions(projectPath, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return false
	}
	return true
}

func ChangedFiles(projectPath string, lastCommitSha string) (object.Changes, error) {
	repo, err := git.PlainOpen(projectPath)
	if err != nil {
		return nil, errors.New("failed to open repo: " + err.Error())
	}
	ref, err := repo.Head()
	if err != nil {
		return nil, errors.New("failed to get HEAD:" + err.Error())
	}
	return DiffCommit(projectPath, ref.Hash().String(), lastCommitSha)
}

func DiffCommit(projectPath string, currentCommitSha string, prevCommitSha string) (object.Changes, error) {
	repo, err := git.PlainOpen(projectPath)
	if err != nil {
		return nil, errors.New("failed to open repo: " + err.Error())
	}
	currentCommit, err := repo.CommitObject(plumbing.NewHash(currentCommitSha))
	if err != nil {
		logger.Error(err.Error())
		return nil, errors.New("failed to parse current commit: " + prevCommitSha)
	}

	prevCommit, err := repo.CommitObject(plumbing.NewHash(prevCommitSha))
	if err != nil {
		logger.Error(err.Error())
		return nil, errors.New("failed to parse prev commit: " + prevCommitSha)
	}
	lastTree, err := prevCommit.Tree()
	if err != nil {
		return nil, errors.New("failed to get last tree: " + err.Error())
	}
	currentTree, err := currentCommit.Tree()
	if err != nil {
		return nil, errors.New("failed to get current tree: " + err.Error())
	}
	return lastTree.Diff(currentTree)
}
