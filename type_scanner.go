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

type SastResult struct {
	Findings []SastFinding
}

type SastScanner interface {
	Name() string
	Type() ScannerType
	Scan(option ScanOption) (*SastResult, error)
}

type ScaResult struct {
	Packages            []Package
	PackageDependencies []PackageDependency
	Vulnerabilities     []Vulnerability
}

type ScaScanner interface {
	Name() string
	Type() ScannerType
	Scan() (*ScaResult, error)
}
