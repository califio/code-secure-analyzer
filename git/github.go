package git

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/califio/code-secure-analyzer/logger"
	"github.com/google/go-github/v74/github"
	"golang.org/x/oauth2"
)

type GitHubEnv struct {
	accessToken string
	client      *github.Client
	ctx         context.Context
}

func NewGitHub() (*GitHubEnv, error) {
	accessToken := os.Getenv("GITHUB_TOKEN")
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	return &GitHubEnv{
		accessToken: accessToken,
		client:      client,
		ctx:         ctx,
	}, nil
}

func (g GitHubEnv) IsActive() bool {
	isActive := os.Getenv("GITHUB_ACTIONS") == "true"
	if isActive {
		logger.Info("GitHub Actions Environment")
		if g.accessToken == "" {
			logger.Warn("GITHUB_TOKEN is not set. Add GITHUB_TOKEN variable to comment on pull request")
		}
	}
	return isActive
}

func (g GitHubEnv) CreateMRDiscussion(option MRDiscussionOption) error {
	prNumberStr := g.MergeRequestID()
	if prNumberStr == "" {
		return errors.New("cannot create discussion without pull request")
	}
	prNumber, err := strconv.Atoi(prNumberStr)
	if err != nil {
		return errors.New("pull request id should be a number")
	}
	ownerRepo := os.Getenv("GITHUB_REPOSITORY")
	parts := strings.Split(ownerRepo, "/")
	if len(parts) != 2 {
		return errors.New("invalid GITHUB_REPOSITORY format")
	}
	owner, repo := parts[0], parts[1]
	comment := &github.IssueComment{Body: &option.Body}
	_, _, err = g.client.Issues.CreateComment(g.ctx, owner, repo, prNumber, comment)
	if err != nil {
		logger.Error("Create comment on pull request failed")
		logger.Error(err.Error())
	} else {
		logger.Info("Created comment: " + option.Title)
	}
	return err
}

func (g GitHubEnv) Provider() string {
	return GitHub
}

func (g GitHubEnv) ProjectID() string {
	return os.Getenv("GITHUB_REPOSITORY")
}

func (g GitHubEnv) ProjectName() string {
	repo := os.Getenv("GITHUB_REPOSITORY")
	parts := strings.Split(repo, "/")
	if len(parts) == 2 {
		return parts[1]
	}
	return repo
}

func (g GitHubEnv) ProjectURL() string {
	return "https://github.com/" + os.Getenv("GITHUB_REPOSITORY")
}

func (g GitHubEnv) CommitTag() string {
	return os.Getenv("GITHUB_REF_NAME")
}

func (g GitHubEnv) CommitBranch() string {
	return os.Getenv("GITHUB_REF_NAME")
}

func (g GitHubEnv) CommitSha() string {
	return os.Getenv("GITHUB_SHA")
}

func (g GitHubEnv) CommitTitle() string {
	return os.Getenv("GITHUB_COMMIT_TITLE")
}

func (g GitHubEnv) DefaultBranch() string {
	return os.Getenv("GITHUB_DEFAULT_BRANCH")
}

func (g GitHubEnv) SourceBranch() string {
	return os.Getenv("GITHUB_HEAD_REF")
}

func (g GitHubEnv) TargetBranch() string {
	return os.Getenv("GITHUB_BASE_REF")
}

func (g GitHubEnv) TargetBranchSha() string {
	prNumberStr := g.MergeRequestID()
	ownerRepo := os.Getenv("GITHUB_REPOSITORY")
	parts := strings.Split(ownerRepo, "/")
	if prNumberStr == "" || len(parts) != 2 {
		return ""
	}
	prNumber, err := strconv.Atoi(prNumberStr)
	if err != nil {
		return ""
	}
	owner, repo := parts[0], parts[1]
	pr, _, err := g.client.PullRequests.Get(g.ctx, owner, repo, prNumber)
	if err != nil || pr.Base == nil || pr.Base.SHA == nil {
		return ""
	}
	return *pr.Base.SHA
}

func (g GitHubEnv) MergeRequestID() string {
	return os.Getenv("GITHUB_PR_NUMBER")
}

func (g GitHubEnv) MergeRequestTitle() string {
	return os.Getenv("GITHUB_PR_TITLE")
}

func (g GitHubEnv) JobURL() string {
	return os.Getenv("GITHUB_RUN_URL")
}
