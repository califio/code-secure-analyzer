package test

import (
	"gitlab.com/code-secure/analyzer/logger"
	"testing"
)

func TestLogger(t *testing.T) {
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
	logger.Println("print")
}
