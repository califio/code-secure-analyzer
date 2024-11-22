package analyzer

type ScannerType string

const (
	ScannerTypeSast            ScannerType = "Sast"
	ScannerTypeDast            ScannerType = "Dast"
	ScannerTypeIast            ScannerType = "Iast"
	ScannerTypeDependency      ScannerType = "Dependency"
	ScannerTypeContainer       ScannerType = "Container"
	ScannerTypeSecretDetection ScannerType = "Secret"
)

type FindingResult struct {
	Findings []Finding
}

type SCAResult struct {
	Packages            []Package
	PackageDependencies []PackageDependency
	Vulnerabilities     []Vulnerability
}

type FindingScanner interface {
	Name() string
	Type() ScannerType
	Scan() (*FindingResult, error)
}

type SCAScanner interface {
	Name() string
	Type() ScannerType
	Scan() (*SCAResult, error)
}
