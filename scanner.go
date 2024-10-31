package main

import "analyzer/finding"

type Scanner interface {
	Scan() ([]finding.Finding, error)
}
