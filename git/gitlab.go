package git

import (
	"errors"
	"github.com/califio/code-secure-analyzer/logger"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"os"
	"strconv"
)

type GitLabEnv struct {
	accessToken string
	serverUrl   string
	client      *gitlab.Client
}

func NewGitLab() (*GitLabEnv, error) {
	accessToken := os.Getenv("GITLAB_TOKEN")
	serverUrl := os.Getenv("CI_SERVER_URL")
	// Initialize the GitLab client
	client, err := gitlab.NewClient(accessToken, gitlab.WithBaseURL(serverUrl))
	if err != nil {
		return nil, err
	}
	return &GitLabEnv{
		accessToken: accessToken,
		serverUrl:   serverUrl,
		client:      client,
	}, nil
}

func (g GitLabEnv) IsActive() bool {
	isActive := os.Getenv("GITLAB_CI") == "true"
	if isActive {
		logger.Info("GitLab CI Environment")
		if g.accessToken == "" {
			logger.Warn("GITLAB_TOKEN is not set. Add GITLAB_TOKEN variable to comment on merge request")
		}
	}
	return isActive
}

func (g GitLabEnv) CreateMRDiscussion(option MRDiscussionOption) error {
	if g.MergeRequestID() == "" {
		return errors.New("cannot create discussion without merge request")
	}
	mergeRequestID, err := strconv.Atoi(g.MergeRequestID())
	if err != nil {
		return errors.New("cannot create discussion. merge request id should be a number")
	}
	projectID := g.ProjectID()
	diffs, _, err := g.client.MergeRequests.ListMergeRequestDiffs(projectID, mergeRequestID, nil)
	if err != nil {
		return err
	}

	mNewPaths := make(map[string]bool)

	for _, diff := range diffs {
		mNewPaths[diff.NewPath] = true
		mNewPaths[diff.OldPath] = true
	}
	mr, _, err := g.client.MergeRequests.GetMergeRequest(projectID, mergeRequestID, nil)
	if err != nil {
		return err
	}
	position := gitlab.PositionOptions{
		BaseSHA:      &mr.DiffRefs.BaseSha,
		StartSHA:     &mr.DiffRefs.StartSha,
		HeadSHA:      &mr.DiffRefs.HeadSha,
		OldPath:      &option.Path,
		NewPath:      &option.Path,
		PositionType: gitlab.Ptr("text"),
		NewLine:      &option.StartLine,
		OldLine:      &option.StartLine,
	}
	_, res, err := g.client.Discussions.CreateMergeRequestDiscussion(
		projectID,
		mergeRequestID,
		&gitlab.CreateMergeRequestDiscussionOptions{
			Body:     &option.Body,
			Position: &position,
		},
	)
	if err != nil || (res != nil && res.StatusCode == 400) {
		position.OldLine = nil
		_, _, err := g.client.Discussions.CreateMergeRequestDiscussion(
			projectID,
			mergeRequestID,
			&gitlab.CreateMergeRequestDiscussionOptions{
				Body:     &option.Body,
				Position: &position,
			},
		)
		if err != nil {
			logger.Error("Create discussion on merge request discussion failure")
			logger.Error(err.Error())
		} else {
			logger.Info("Created discussion: " + option.Title)
		}
	} else {
		logger.Info("Created discussion: " + option.Title)
	}
	return nil
}

func (g GitLabEnv) Provider() string {
	return GitLab
}

func (g GitLabEnv) ProjectID() string {
	return os.Getenv("CI_PROJECT_ID")
}

func (g GitLabEnv) ProjectName() string {
	return os.Getenv("CI_PROJECT_NAME")
}

func (g GitLabEnv) ProjectURL() string {
	return os.Getenv("CI_PROJECT_URL")
}

func (g GitLabEnv) CommitTag() string {
	return os.Getenv("CI_COMMIT_TAG")
}

func (g GitLabEnv) CommitBranch() string {
	return os.Getenv("CI_COMMIT_BRANCH")
}

func (g GitLabEnv) CommitSha() string {
	return os.Getenv("CI_COMMIT_SHA")
}

func (g GitLabEnv) CommitTitle() string {
	return os.Getenv("CI_COMMIT_TITLE")
}

func (g GitLabEnv) DefaultBranch() string {
	return os.Getenv("CI_DEFAULT_BRANCH")
}

func (g GitLabEnv) SourceBranch() string {
	return os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
}

func (g GitLabEnv) TargetBranch() string {
	return os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
}

func (g GitLabEnv) TargetBranchSha() string {
	return os.Getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
}

func (g GitLabEnv) MergeRequestID() string {
	return os.Getenv("CI_MERGE_REQUEST_IID")
}

func (g GitLabEnv) MergeRequestTitle() string {
	return os.Getenv("CI_MERGE_REQUEST_TITLE")
}

func (g GitLabEnv) JobURL() string {
	return os.Getenv("CI_JOB_URL")
}
