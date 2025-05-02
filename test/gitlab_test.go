package test

import (
	"os"
	"testing"
)

func TestCommentSASTMergeRequest(t *testing.T) {
	os.Setenv("CI_SERVER_URL", "https://gitlab.com")
	os.Setenv("GITLAB_TOKEN", "")
	os.Setenv("CI_PROJECT_ID", "50471840")
	os.Setenv("CI_PROJECT_URL", "https://gitlab.com/0xduo/vulnado")
	os.Setenv("CI_COMMIT_SHA", "72155d553d00f913d1e9b64def483724493da19e")

}
