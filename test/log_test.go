package test

import (
	"context"
	"fmt"
	"gitlab.com/code-secure/analyzer"
	"gitlab.com/code-secure/analyzer/logger"
	"testing"
)

func TestLogger(t *testing.T) {
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
	logger.Println("print")
}

func T(context context.Context) {
	text := fmt.Sprintf("%s", context.Value("server"))
	fmt.Println(text)
}

func TestSaveresult(t *testing.T) {
	var result *analyzer.UploadFindingResponse
	result = &analyzer.UploadFindingResponse{
		IsBlock: true,
	}
	analyzer.SaveFindingResult(*result)
}
