package main

import "analyzer/finding"

type DefaultHandler struct{}

func (receiver *DefaultHandler) Classify(findings []finding.Finding) FindingType {
	return FindingType{
		NewFindings: findings,
	}
}
