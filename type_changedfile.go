package analyzer

import (
	"errors"
	"github.com/califio/code-secure-analyzer/logger"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/utils/merkletrie"
)

type ChangedFileStatus string

const Add ChangedFileStatus = "Add"
const Modify ChangedFileStatus = "Modify"
const Delete ChangedFileStatus = "Delete"

type ChangedFile struct {
	From   string            `json:"from"`
	To     string            `json:"to"`
	Status ChangedFileStatus `json:"status"`
}

func FromObjectChanges(changes object.Changes) []ChangedFile {
	var filesChange []ChangedFile
	for _, change := range changes {
		action, err := change.Action()
		if err != nil {
			logger.Error("failed to get type file change: " + err.Error())
			continue
		}
		status, err := getFileState(action)
		if err != nil {
			logger.Error("failed to get file state: " + err.Error())
			continue
		}
		filesChange = append(filesChange, ChangedFile{
			From:   change.From.Name,
			To:     change.To.Name,
			Status: status,
		})
	}
	return filesChange
}

func getFileState(action merkletrie.Action) (ChangedFileStatus, error) {
	if action == merkletrie.Insert {
		return Add, nil
	}
	if action == merkletrie.Modify {
		return Modify, nil
	}
	if action == merkletrie.Delete {
		return Delete, nil
	}
	return Add, errors.New("unknown file state")
}
