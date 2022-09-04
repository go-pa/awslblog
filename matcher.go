package awslblog

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
)

var (
	// NOTE: go regexps are not super fast, room for improvement by not using a
	// regular expression.
	lineMatcher       = regexp.MustCompile(`(?P<type>[^ ]*) (?P<time>[^ ]*) (?P<elb>[^ ]*) (?P<client_ip>[^ ]*):(?P<client_port>[0-9]*) (?P<target_ip>[^ ]*)[:-](?P<target_port>[0-9]*) (?P<req_processing_time>[-.0-9]*) (?P<target_processing_time>[-.0-9]*) (?P<response_processing_time>[-.0-9]*) (?P<elb_status_code>|[-0-9]*) (?P<target_status_code>-|[-0-9]*) (?P<recv_bytes>[-0-9]*) (?P<sent_bytes>[-0-9]*) \"(?P<req_verb>[^ ]*) (?P<req_url>.*) (?P<req_proto>- |[^ ]*)\" \"(?P<user_agent>[^\"]*)\" (?P<ssl_chipher>[A-Z0-9-_]+) (?P<ssl_protocol>[A-Za-z0-9.-]*) (?P<target_group_arn>[^ ]*) \"(?P<trace_id>[^\"]*)\" \"(?P<domain_name>[^\"]*)\" \"(?P<chosen_cert_arn>[^\"]*)\" (?P<matched_module_priority>[-.0-9]*) (?P<requested_creation_time>[^ ]*) \"(?P<actions_executed>[^\"]*)\" \"(?P<redirect_url>[^\"]*)\" \"(?P<lambda_error_reason>[^ ]*)\" \"(?P<target_port_list>[^\s]+?)\" \"(?P<target_status_code_list>[^\s]+)\" \"(?P<classification>[^ ]*)\" \"(?P<classification_reason>[^ ]*)\"`)
	lineMatcherFields = lineMatcher.SubexpNames()
	lineMatcherLength = len(lineMatcherFields)
)

type Match [33]string

//go:generate go run github.com/dmarkham/enumer@v1.5.6 -type=MatchColumn -trimprefix Column -json
type MatchColumn int

const (
	ColumnType MatchColumn = iota
	ColumnTime
	ColumnELB
	ColumnClientIP
	ColumnClientPort
	ColumnTargetIP
	ColumnTargetPort
	ColumnRequestProcessingTime
	ColumnTargetProcessingTime
	ColumnResponseProcessingTime
	ColumnELBStatusCode
	ColumnTargetStatusCode
	ColumnReceivedBytes
	ColumnSentBytes
	ColumnRequestVerb
	ColumnRequestURL
	ColumnRequestProto
	ColumnUserAgent
	ColumnSSLCipher
	ColumnSSLProtocol
	ColumnTargetGroupArn
	ColumnTraceId
	ColumnDomainName
	ColumnChosenCertArn
	ColumnMatchedRulePriority
	ColumnRequestCreationTime
	ColumnActionsExecuted
	ColumnRedirectURL
	ColumnLambdaErrorReason
	ColumnTargetPortList
	ColumnTargetStatusCodeList
	ColumnClassification
	ColumnClassificationReason
)

// Matcher .
type Matcher struct {
	s       *bufio.Scanner
	current Match
	err     error
}

func NewMatcher(r io.Reader) *Matcher {
	return &Matcher{
		s: bufio.NewScanner(r),
	}
}

// Next runs the matcher on the next line.
//
// Returns true if there are more matches or no errors.
func (m *Matcher) Next() bool {
	if m.err != nil {
		return false
	}
	s := m.s.Scan()
	if !s {

		m.err = m.s.Err()
		return false
	}

	line := m.s.Text()
	ms := lineMatcher.FindStringSubmatch(line)
	if len(ms) != lineMatcherLength {
		m.err = fmt.Errorf("wrong number of matching fields: %s", line)
		return false
	}
	copy(m.current[:], ms[1:])
	return true
}

// Err returns the current error.
func (m *Matcher) Err() error {
	return m.err
}

// Match returns the value of the current match.
func (m *Matcher) Match() Match {
	return m.current
}
