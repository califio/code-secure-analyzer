package analyzer

import "os"

func Ptr[T any](v T) *T {
	return &v
}

func IsDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
