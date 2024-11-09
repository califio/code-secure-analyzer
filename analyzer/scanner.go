package analyzer

// Scanner Finding is SASTFinding or SCAFinding,...
type Scanner[T any] interface {
	Scan() ([]T, error)
	Name() string
}
