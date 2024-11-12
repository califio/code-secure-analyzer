package test

import (
	"context"
	"fmt"
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

func TestContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), "server", "http://gitlab")
	T(ctx)
}
