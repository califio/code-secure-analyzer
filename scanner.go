package analyzer

type SASTResult struct {
	Findings []Finding
}

type SCAResult struct {
	Packages            []Package
	PackageDependencies []PackageDependency
	Vulnerabilities     []Vulnerability
}

type SASTScanner interface {
	Name() string
	Scan() (*SASTResult, error)
}

type DependencyScanner interface {
	Name() string
	Scan() (*SCAResult, error)
}
