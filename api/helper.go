package api

func Ptr[T any](v T) *T {
	return &v
}
