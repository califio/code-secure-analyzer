package analyzer

type Package struct {
	Id       *string `json:"id,omitempty"`
	PkgId    string  `json:"pkgId,omitempty"`
	Group    string  `json:"group,omitempty"`
	Name     string  `json:"name,omitempty"`
	Version  string  `json:"version,omitempty"`
	Type     string  `json:"type,omitempty"`
	License  string  `json:"license,omitempty"`
	Location *string `json:"location,omitempty"`
}

type PackageDependency struct {
	PkgId        string   `json:"pkgId,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type PackageInfo struct {
	Package         Package         `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Identity     string
	Name         string
	Description  string
	FixedVersion string
	Severity     string
	PkgId        string
	PkgName      string
	PublishedAt  *string
	Metadata     *FindingMetadata
}
