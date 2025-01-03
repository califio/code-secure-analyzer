package analyzer

import (
	"context"
	"fmt"
	"github.com/califio/code-secure-analyzer/logger"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"os"
	"strconv"
)

func NewGitlab() (*Gitlab, error) {
	accessToken := os.Getenv("GITLAB_TOKEN")
	serverUrl := os.Getenv("CI_SERVER_URL") // Use your GitLab instance URL if self-hosted
	// Initialize the GitLab client
	client, err := gitlab.NewClient(accessToken, gitlab.WithBaseURL(serverUrl))
	if err != nil {
		return nil, err
	}
	return &Gitlab{
		accessToken: accessToken,
		ServerURL:   serverUrl,
		client:      client,
	}, nil
}

type Gitlab struct {
	accessToken string
	ServerURL   string
	client      *gitlab.Client
}

func (g *Gitlab) Name() string {
	return "GitLab"
}
func (g *Gitlab) AccessToken() string {
	return g.accessToken
}
func (g *Gitlab) CommentFindingOnMergeRequest(context context.Context, findings []Finding, mergeRequest *MergeRequest) error {
	projectID := g.ProjectID()
	// Merge Request IID (not the project-wide MR ID)
	mergeRequestID, _ := strconv.Atoi(mergeRequest.MergeRequestID)
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
	// Create a new discussion each finding
	projectUrl := g.ProjectURL()
	commitSha := g.CommitHash()
	for _, f := range findings {
		location := getLocation(f, mNewPaths)
		if location != nil {
			locationUrl := fmt.Sprintf("%s/-/blob/%s/%s#L%d", projectUrl, commitSha, location.Path, location.StartLine)
			remoteFindingUrl := fmt.Sprintf("%s/#/finding/%s", context.Value("server"), f.ID)
			msg := fmt.Sprintf("**[%s](%s)**\n\n**Location:** `%s` @ [%s](%s)\n\n**Description**\n\n%s", f.Name, remoteFindingUrl, location.Snippet, location.Path, locationUrl, f.Description)
			if f.Recommendation != "" {
				msg += fmt.Sprintf("\n\n**Recommendation**\n\n %s", f.Recommendation)
			}
			if f.Metadata != nil && len(f.Metadata.FindingFlow) > 0 {
				flow := ""
				for index, step := range f.Metadata.FindingFlow {
					url := fmt.Sprintf("%s/-/blob/%s/%s#L%d", projectUrl, commitSha, step.Path, step.StartLine)
					flow += fmt.Sprintf("%d. `%s` @ [%s](%s)\n", index+1, step.Snippet, step.Path, url)
				}
				codeFlow := fmt.Sprintf("\n\n<details>\n<summary>Finding Flow</summary>\n\n%s\n</details>", flow)
				msg += codeFlow
			}
			position := gitlab.PositionOptions{
				BaseSHA:      &mr.DiffRefs.BaseSha,
				StartSHA:     &mr.DiffRefs.StartSha,
				HeadSHA:      &mr.DiffRefs.HeadSha,
				OldPath:      &location.Path,
				NewPath:      &location.Path,
				PositionType: gitlab.Ptr("text"),
				NewLine:      &location.StartLine,
				OldLine:      &location.StartLine,
			}
			_, res, err := g.client.Discussions.CreateMergeRequestDiscussion(
				projectID,
				mergeRequestID,
				&gitlab.CreateMergeRequestDiscussionOptions{
					Body:     &msg,
					Position: &position,
				},
			)
			if err != nil || (res != nil && res.StatusCode == 400) {
				position.OldLine = nil
				_, _, err := g.client.Discussions.CreateMergeRequestDiscussion(
					projectID,
					mergeRequestID,
					&gitlab.CreateMergeRequestDiscussionOptions{
						Body:     &msg,
						Position: &position,
					},
				)
				if err != nil {
					logger.Error("Create discussion on merge request discussion failure")
					logger.Error(err.Error())
				} else {
					logger.Info("Create discussion: " + f.Name)
				}
			} else {
				logger.Info("Create discussion: " + f.Name)
			}
		}
	}
	return nil
}

func (g *Gitlab) IsActive() bool {
	isActive := os.Getenv("GITLAB_CI") == "true"
	if isActive {
		logger.Info("GitLab CI environment")
		if g.accessToken == "" {
			logger.Warn("GITLAB_TOKEN is not set. Add GITLAB_TOKEN variable to comment on merge request")
		}
	}
	return isActive
}

func (g *Gitlab) ProjectID() string {
	return os.Getenv("CI_PROJECT_ID")
}

func (g *Gitlab) ProjectName() string {
	return os.Getenv("CI_PROJECT_NAME")
}

func (g *Gitlab) ProjectGroup() string {
	return os.Getenv("CI_PROJECT_NAMESPACE")
}

func (g *Gitlab) ProjectURL() string {
	return os.Getenv("CI_PROJECT_URL")
}

func (g *Gitlab) MergeRequest() *MergeRequest {
	if os.Getenv("CI_MERGE_REQUEST_IID") != "" {
		return &MergeRequest{
			SourceBranch:      os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"),
			SourceBranchHash:  os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"),
			TargetBranch:      os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
			TargetBranchHash:  os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_SHA"),
			MergeRequestID:    os.Getenv("CI_MERGE_REQUEST_IID"),
			MergeRequestTitle: os.Getenv("CI_MERGE_REQUEST_TITLE"),
		}
	}
	return nil
}

func (g *Gitlab) CommitTag() string {
	return os.Getenv("CI_COMMIT_TAG")
}

func (g *Gitlab) CommitBranch() string {
	return os.Getenv("CI_COMMIT_BRANCH")
}

func (g *Gitlab) CommitHash() string {
	return os.Getenv("CI_COMMIT_SHA")
}

func (g *Gitlab) CommitTitle() string {
	return os.Getenv("CI_COMMIT_TITLE")
}

func (g *Gitlab) DefaultBranch() string {
	return os.Getenv("CI_DEFAULT_BRANCH")
}

func (g *Gitlab) JobURL() string {
	return os.Getenv("CI_JOB_URL")
}

func getLocation(finding Finding, mPath map[string]bool) *FindingLocation {
	if mPath[finding.Location.Path] {
		return finding.Location
	}
	if finding.Metadata == nil {
		return nil
	}
	for i := len(finding.Metadata.FindingFlow) - 1; i >= 0; i-- {
		if mPath[finding.Metadata.FindingFlow[i].Path] {
			return &finding.Metadata.FindingFlow[i]
		}
	}
	return nil
}
