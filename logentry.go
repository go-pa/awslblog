package awslblog

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// LogEntry represents a line of an ELB application access log.
//
// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-log-entry-format
type LogEntry struct {
	Type                   string    `json:"type"`
	Time                   time.Time `json:"time"`
	ELB                    string    `json:"elb"`
	ClientIP               net.IP    `json:"client_ip"`
	ClientPort             int       `json:"client_port"`
	TargetIP               net.IP    `json:"target_ip"`
	TargetPort             int       `json:"target_port"`
	RequestProcessingTime  float64   `json:"request_processing_time"`
	TargetProcessingTime   float64   `json:"target_processing_time"`
	ResponseProcessingTime float64   `json:"response_processing_time"`
	ELBStatusCode          int       `json:"elb_status_code"`
	TargetStatusCode       string    `json:"target_status_code"`
	ReceivedBytes          int       `json:"received_bytes"`
	SentBytes              int       `json:"sent_bytes"`
	RequestVerb            string    `json:"request_verb"`
	RequestURL             string    `json:"request_url"`
	RequestProto           string    `json:"request_proto"`
	UserAgent              string    `json:"user_agent"`
	SSLCipher              string    `json:"ssl_cipher"`
	SSLProtocol            string    `json:"ssl_protocol"`
	TargetGroupArn         string    `json:"target_group_arn"`
	TraceId                string    `json:"trace_id"`
	DomainName             string    `json:"domain_name"`
	ChosenCertArn          string    `json:"chosen_cert_arn"`
	MatchedRulePriority    string    `json:"matched_rule_priority"`
	RequestCreationTime    time.Time `json:"request_creation_time"`
	ActionsExecuted        string    `json:"actions_executed"`
	RedirectURL            string    `json:"redirect_url"`
	LambdaErrorReason      string    `json:"lambda_error_reason"`
	TargetPortList         string    `json:"target_port_list"`
	TargetStatusCodeList   string    `json:"target_status_code_list"`
	Classification         string    `json:"classification"`
	ClassificationReason   string    `json:"classification_reason"`
}

// ParseLogEntry parses a egexp match to a LogEntry.
//
// m is expected to be of the required length.
func ParseLogEntry(m Match) (LogEntry, error) {
	timestamp, err := time.Parse(time.RFC3339Nano, m[ColumnTime])
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse timestamp: %w", err)
	}
	requestCreationTime, err := time.Parse(time.RFC3339Nano, m[ColumnRequestCreationTime])
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse request creation time: %w", err)
	}
	clientPort := 0
	if m[ColumnClientPort] != "" {
		clientPort, err = strconv.Atoi(m[ColumnClientPort])
		if err != nil {
			return LogEntry{}, fmt.Errorf("could not parse client port: %w", err)
		}
	}
	targetPort := 0
	if m[ColumnTargetPort] != "" {
		targetPort, err = strconv.Atoi(m[ColumnTargetPort])
		if err != nil {
			return LogEntry{}, fmt.Errorf("could not parse target port: %w", err)
		}
	}
	requestProcessingTime, err := strconv.ParseFloat(m[ColumnRequestProcessingTime], 64)
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse request processing time: %w", err)
	}

	targetProcessingTime, err := strconv.ParseFloat(m[ColumnTargetProcessingTime], 64)
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse target processing time: %w", err)
	}

	responseProcessingTime, err := strconv.ParseFloat(m[ColumnResponseProcessingTime], 64)
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse response processing time: %w", err)
	}

	elbStatusCode, err := strconv.Atoi(m[ColumnELBStatusCode])
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse elb status code: %w", err)
	}

	recvBytes, err := strconv.Atoi(m[ColumnReceivedBytes])
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse received bytes: %w", err)
	}

	sentBytes, err := strconv.Atoi(m[ColumnSentBytes])
	if err != nil {
		return LogEntry{}, fmt.Errorf("could not parse sent bytes: %w", err)
	}

	le := LogEntry{
		Type:                   m[ColumnType],
		Time:                   timestamp,
		ELB:                    m[ColumnELB],
		ClientIP:               net.ParseIP(m[ColumnClientIP]),
		ClientPort:             clientPort,
		TargetIP:               net.ParseIP(m[ColumnTargetIP]),
		TargetPort:             targetPort,
		RequestProcessingTime:  requestProcessingTime,
		TargetProcessingTime:   targetProcessingTime,
		ResponseProcessingTime: responseProcessingTime,
		ELBStatusCode:          elbStatusCode,
		TargetStatusCode:       m[ColumnTargetStatusCode],
		ReceivedBytes:          recvBytes,
		SentBytes:              sentBytes,
		RequestVerb:            m[ColumnRequestVerb],
		RequestURL:             m[ColumnRequestURL],
		RequestProto:           m[ColumnRequestProto],
		UserAgent:              m[ColumnUserAgent],
		SSLCipher:              m[ColumnSSLCipher],
		SSLProtocol:            m[ColumnSSLProtocol],
		TargetGroupArn:         m[ColumnTargetGroupArn],
		TraceId:                m[ColumnTraceId],
		DomainName:             m[ColumnDomainName],
		ChosenCertArn:          m[ColumnChosenCertArn],
		MatchedRulePriority:    m[ColumnMatchedRulePriority],
		RequestCreationTime:    requestCreationTime,
		ActionsExecuted:        m[ColumnActionsExecuted],
		RedirectURL:            m[ColumnRedirectURL],
		LambdaErrorReason:      m[ColumnLambdaErrorReason],
		TargetPortList:         m[ColumnTargetPortList],
		TargetStatusCodeList:   m[ColumnTargetStatusCodeList],
		Classification:         m[ColumnClassification],
		ClassificationReason:   m[ColumnClassificationReason],
	}
	return le, nil
}

// LogEntries is a list of LogEntry.
type LogEntries []LogEntry

var divider = strings.Repeat("-", 79)

func (l LogEntry) PrettyPrint(w io.Writer) {
	fmt.Fprintln(w, divider)
	fmt.Fprintln(w, "Type                   ", l.Type)
	fmt.Fprintln(w, "Time                   ", l.Time)
	fmt.Fprintln(w, "ELB                    ", l.ELB)
	fmt.Fprintln(w, "ClientIP               ", l.ClientIP)
	fmt.Fprintln(w, "ClientPort             ", l.ClientPort)
	fmt.Fprintln(w, "TargetIP               ", l.TargetIP)
	fmt.Fprintln(w, "TargetPort             ", l.TargetPort)
	fmt.Fprintln(w, "RequestProcessingTime  ", l.RequestProcessingTime)
	fmt.Fprintln(w, "TargetProcessingTime   ", l.TargetProcessingTime)
	fmt.Fprintln(w, "ResponseProcessingTime ", l.ResponseProcessingTime)
	fmt.Fprintln(w, "ELBStatusCode          ", l.ELBStatusCode)
	fmt.Fprintln(w, "TargetStatusCode       ", l.TargetStatusCode)
	fmt.Fprintln(w, "ReceivedBytes          ", l.ReceivedBytes)
	fmt.Fprintln(w, "SentBytes              ", l.SentBytes)
	fmt.Fprintln(w, "RequestVerb            ", l.RequestVerb)
	fmt.Fprintln(w, "RequestURL             ", l.RequestURL)
	fmt.Fprintln(w, "RequestProto           ", l.RequestProto)
	fmt.Fprintln(w, "UserAgent              ", l.UserAgent)
	fmt.Fprintln(w, "SSLCipher              ", l.SSLCipher)
	fmt.Fprintln(w, "SSLProtocol            ", l.SSLProtocol)
	fmt.Fprintln(w, "TargetGroupArn         ", l.TargetGroupArn)
	fmt.Fprintln(w, "TraceID                ", l.TraceId)
	fmt.Fprintln(w, "DomainName             ", l.DomainName)
	fmt.Fprintln(w, "ChosenCertArn          ", l.ChosenCertArn)
	fmt.Fprintln(w, "MatchedRulePriority    ", l.MatchedRulePriority)
	fmt.Fprintln(w, "RequestCreationTime    ", l.RequestCreationTime)
	fmt.Fprintln(w, "ActionsExecuted        ", l.ActionsExecuted)
	fmt.Fprintln(w, "RedirectURL            ", l.RedirectURL)
	fmt.Fprintln(w, "LambdaErrorReason      ", l.LambdaErrorReason)
	fmt.Fprintln(w, "TargetPortList         ", l.TargetPortList)
	fmt.Fprintln(w, "TargetStatusCodeList   ", l.TargetStatusCodeList)
	fmt.Fprintln(w, "Classification         ", l.Classification)
	fmt.Fprintln(w, "ClassificationReason   ", l.ClassificationReason)
}
