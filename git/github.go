package git

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/califio/code-secure-analyzer/logger"
	"github.com/google/go-github/v74/github"
	"golang.org/x/oauth2"
)

type GitHubEnv struct {
	accessToken  string
	client       *github.Client
	ctx          context.Context
	eventPayload eventPayload
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
		accessToken:  accessToken,
		client:       client,
		ctx:          ctx,
		eventPayload: getEventPayload(),
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
	comment := github.DraftReviewComment{
		Path: github.Ptr(option.Path),
		Body: github.Ptr(option.Body),
	}
	if option.StartLine == option.EndLine {
		logger.Info("same line")
		comment.Line = github.Ptr(option.StartLine)
	} else {
		logger.Info("diff line")
		comment.StartLine = github.Ptr(option.StartLine)
		comment.Line = github.Ptr(option.EndLine)
	}
	review := &github.PullRequestReviewRequest{
		Body:  &option.Title,
		Event: github.Ptr("COMMENT"),
		Comments: []*github.DraftReviewComment{
			&comment,
		},
	}
	_, _, err = g.client.PullRequests.CreateReview(g.ctx, owner, repo, prNumber, review)
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
	return os.Getenv("GITHUB_REPOSITORY_ID")
}

func (g GitHubEnv) ProjectName() string {
	return os.Getenv("GITHUB_REPOSITORY")
}

func (g GitHubEnv) ProjectURL() string {
	return fmt.Sprintf("%s/%s", os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"))
}

func (g GitHubEnv) BlobURL() string {
	return fmt.Sprintf("%s/blob", g.ProjectURL())
}

func (g GitHubEnv) CommitTag() string {
	if os.Getenv("GITHUB_REF_TYPE") == "tag" {
		return os.Getenv("GITHUB_REF_NAME")
	}
	return ""
}

func (g GitHubEnv) CommitBranch() string {
	if g.MergeRequestID() != "" {
		return g.eventPayload.PullRequest.Head.Ref
	}
	if os.Getenv("GITHUB_REF_TYPE") == "branch" {
		return os.Getenv("GITHUB_REF_NAME")
	}
	return ""
}

func (g GitHubEnv) CommitSha() string {
	return os.Getenv("GITHUB_SHA")
}

func (g GitHubEnv) CommitTitle() string {
	if os.Getenv("GITHUB_COMMIT_TITLE") != "" {
		return os.Getenv("GITHUB_COMMIT_TITLE")
	}
	if g.eventPayload.HeadCommit != nil {
		return g.eventPayload.HeadCommit.Message
	}
	return ""
}

func (g GitHubEnv) DefaultBranch() string {
	if os.Getenv("GITHUB_DEFAULT_BRANCH") != "" {
		return os.Getenv("GITHUB_DEFAULT_BRANCH")
	}

	if g.eventPayload.Repository != nil {
		return g.eventPayload.Repository.DefaultBranch
	}
	return "main"
}

func (g GitHubEnv) SourceBranch() string {
	return os.Getenv("GITHUB_HEAD_REF")
}

func (g GitHubEnv) TargetBranch() string {
	return os.Getenv("GITHUB_BASE_REF")
}

func (g GitHubEnv) TargetBranchSha() string {
	if os.Getenv("GITHUB_BASE_REF_SHA") != "" {
		return os.Getenv("GITHUB_BASE_REF_SHA")
	}
	if g.eventPayload.PullRequest != nil {
		return g.eventPayload.PullRequest.Base.Sha
	}
	return ""
}

func (g GitHubEnv) MergeRequestID() string {
	if os.Getenv("GITHUB_PR_NUMBER") != "" {
		return os.Getenv("GITHUB_PR_NUMBER")
	}
	if g.eventPayload.PullRequest != nil {
		return strconv.Itoa(g.eventPayload.PullRequest.Number)
	}
	return ""
}

func (g GitHubEnv) MergeRequestTitle() string {
	if os.Getenv("GITHUB_PR_TITLE") != "" {
		return os.Getenv("GITHUB_PR_TITLE")
	}
	if g.eventPayload.PullRequest != nil {
		return g.eventPayload.PullRequest.Title
	}
	return ""
}

func (g GitHubEnv) JobURL() string {
	return fmt.Sprintf("%s/%s/actions/runs/%s", os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID"))
}

func getEventPayload() eventPayload {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	_, err := os.Stat(eventPath)
	if err != nil {
		logger.Fatal(fmt.Sprintf("GITHUB_EVENT_PATH (%s) not found", eventPath))
	}
	data, err := os.ReadFile(eventPath)
	if err != nil {
		logger.Fatal(fmt.Sprintf("read GITHUB_EVENT_PATH error: %s", err.Error()))
	}
	var payload eventPayload
	err = json.Unmarshal(data, &payload)
	if err != nil {
		logger.Fatal(err.Error())
	}
	return payload
}

type eventPayload struct {
	PullRequest *pullRequest `json:"pull_request"`
	Repository  *repository  `json:"repository"`
	HeadCommit  *headCommit  `json:"head_commit"`
}

type pullRequest struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Base   struct {
		Ref string `json:"ref"`
		Sha string `json:"sha"`
	} `json:"base"`
	Head struct {
		Ref string `json:"ref"`
		Sha string `json:"sha"`
	} `json:"head"`
}

type headCommit struct {
	Id      string `json:"id"` // this is commit sha
	Message string `json:"message"`
}
type repository struct {
	Id            int    `json:"id"`
	Name          string `json:"name"`
	DefaultBranch string `json:"default_branch"`
	MasterBranch  string `json:"master_branch"`
}
