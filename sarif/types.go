package sarif

import (
	"gitlab.com/code-secure/analyzer/finding"
	"regexp"
	"strings"
)

// match CWE-XXX only
var cweIDRegex = regexp.MustCompile(`([cC][wW][eE])-(\d{1,4})`)

// match (TYPE)-(ID): (Description)
var tagIDRegex = regexp.MustCompile(`([^-]+)-([^:]+):\s*(.+)`)

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Invocations []invocation `json:"invocations"`
	Results     []Result     `json:"results"`
	Tool        struct {
		Driver struct {
			Name            string `json:"name"`
			SemanticVersion string `json:"semanticVersion"`
			Rules           []Rule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
}

type invocation struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	ToolExecutionNotifications []notification `json:"toolExecutionNotifications"`
}

type notification struct {
	Descriptor struct {
		ID string `json:"id"`
	} `json:"descriptor"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
}

type Result struct {
	RuleID  string `json:"ruleId"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	} `json:"locations"`
	Fingerprints struct {
		Id string `json:"matchBasedId/v1"`
	} `json:"fingerprints"`
	CodeFlows    []codeFlow `json:"codeFlows"`
	Suppressions []struct {
		Kind   string `json:"kind"`             // values= 'inSource', 'external'
		Status string `json:"status,omitempty"` // values= empty,'accepted','underReview','rejected'
		GUID   string `json:"guid,omitempty"`
	} `json:"suppressions,omitempty"`
}

func (result *Result) GetCodeFlow() []finding.Location {
	if result.CodeFlows == nil || len(result.CodeFlows) == 0 {
		return nil
	}
	threadFlows := result.CodeFlows[0].ThreadFlows
	if len(threadFlows) == 0 {
		return nil
	}
	var locations []finding.Location
	for _, location := range threadFlows[0].Locations {
		/*
			need to parse message to find real location
			this is the bug of semgrep. see here: https://github.com/semgrep/semgrep/issues/7935
		*/
		physical := location.Location.PhysicalLocation
		message := location.Location.Message.Text
		path := getPathFromMessage(message)
		if path == "" {
			path = physical.ArtifactLocation.Uri
		}
		locations = append(locations, finding.Location{
			Path:        path,
			Snippet:     physical.Region.Snippet.Text,
			StartLine:   physical.Region.StartLine,
			EndLine:     physical.Region.EndLine,
			StartColumn: physical.Region.StartColumn,
			EndColumn:   physical.Region.EndColumn,
		})
	}
	return locations
}

func getPathFromMessage(message string) string {
	arr := strings.Split(message, "@")
	if len(arr) != 2 {
		return ""
	}
	path := strings.Trim(arr[1], " '")
	arr = strings.Split(path, ":")
	if len(arr) != 2 {
		return ""
	}
	return arr[0]
}

type physicalLocation struct {
	ArtifactLocation struct {
		Uri string `json:"uri"`
	} `json:"artifactLocation"`
	Region struct {
		EndColumn int `json:"endColumn"`
		EndLine   int `json:"endLine"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Snippet struct {
			Text string `json:"text"`
		} `json:"snippet"`
		StartColumn int `json:"startColumn"`
		StartLine   int `json:"startLine"`
	} `json:"region"`
}

type codeFlow struct {
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	ThreadFlows []struct {
		Locations []struct {
			Location struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				PhysicalLocation physicalLocation `json:"physicalLocation"`
			} `json:"location"`
			NestingLevel int `json:"nestingLevel"`
		} `json:"locations"`
	} `json:"threadFlows"`
}

type Rule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties ruleProperties `json:"properties"`
	HelpURI    string         `json:"helpUri"`
	Help       struct {
		Markdown string `json:"markdown"`
		Text     string `json:"text"`
	} `json:"help"`
}

type ruleProperties struct {
	Precision        string   `json:"precision"`
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

func findTagMatches(tag string) []string {
	// first try to extract (TAG)-(ID): (Description)
	matches := tagIDRegex.FindStringSubmatch(tag)

	if matches == nil {
		// see if we just have a CWE-(XXX) tag
		matches = cweIDRegex.FindStringSubmatch(tag)
	}
	return matches
}

func (r *Rule) Message() string {
	// prefer shortDescription field over tag: CWE: <text> for semgrep
	if r.ShortDescription.Text != "" && !strings.EqualFold(r.FullDescription.Text, r.ShortDescription.Text) {
		return r.ShortDescription.Text
	}

	for _, tag := range r.Properties.Tags {
		splits := strings.Split(tag, ":")
		if strings.HasPrefix(splits[0], "CWE") && len(splits) > 1 {
			return strings.TrimLeft(splits[1], " ")
		}
	}
	// default.json to full text description
	return r.FullDescription.Text
}

func (r *Rule) Severity() string {
	switch r.DefaultConfiguration.Level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	default:
		return "info"
	}
}
