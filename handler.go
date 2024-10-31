package main

import "analyzer/finding"

type FindingType struct {
	NewFindings   []finding.Finding
	FixedFindings []finding.Finding
	OldFindings   []finding.Finding
}

type Handler interface {
	Classify(findings []finding.Finding) FindingType
}
