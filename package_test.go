package awslblog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestMatchAndParse(t *testing.T) {
	const (
		testline = `https 2022-02-17T04:15:00.493212Z app/something/1234567890abcdef 51.132.188.29:63842 10.0.4.233:80 0.000 0.943 0.000 200 200 404 23441 "GET https://i.example.com:443/unsafe/260x0/filters:no_upscale():format(jpg):fill(fff,1)/foo.png HTTP/1.1" "Amazon CloudFront" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:eu-central-1:999111222333:targetgroup/something/19328f2048294729 "Root=1-620dcbc3-3b4ee4173222f4310fb3c6ec" "i.example.com" "session-reused" 0 2022-02-17T04:14:59.549000Z "forward" "-" "-" "10.0.4.233:80" "200" "-" "-"
`
	)
	ms := NewMatcher(bytes.NewReader([]byte(testline)))
	if !ms.Next() {
		t.Fatal("expected match")
	}

	m := ms.Match()
	// t.Log(m)
	t.Run("parse-logentry", func(t *testing.T) {
		le, err := ParseLogEntry(m)
		if err != nil {
			t.Error(err)
		}
		want := LogEntry{
			Type:                   "https",
			Time:                   time.Date(2022, time.February, 17, 4, 15, 0, 493212000, time.UTC),
			ELB:                    "app/something/1234567890abcdef",
			ClientIP:               net.ParseIP("51.132.188.29"),
			ClientPort:             63842,
			TargetIP:               net.ParseIP("10.0.4.233"),
			TargetPort:             80,
			RequestProcessingTime:  0,
			TargetProcessingTime:   0.943,
			ResponseProcessingTime: 0,
			ELBStatusCode:          200,
			TargetStatusCode:       "200",
			ReceivedBytes:          404,
			SentBytes:              23441,
			RequestVerb:            "GET",
			RequestURL:             "https://i.example.com:443/unsafe/260x0/filters:no_upscale():format(jpg):fill(fff,1)/foo.png",
			RequestProto:           "HTTP/1.1",
			UserAgent:              "Amazon CloudFront",
			SSLCipher:              "ECDHE-RSA-AES128-GCM-SHA256",
			SSLProtocol:            "TLSv1.2",
			TargetGroupArn:         "arn:aws:elasticloadbalancing:eu-central-1:999111222333:targetgroup/something/19328f2048294729",
			TraceId:                "Root=1-620dcbc3-3b4ee4173222f4310fb3c6ec",
			DomainName:             "i.example.com",
			ChosenCertArn:          "session-reused",
			MatchedRulePriority:    "0",
			RequestCreationTime:    time.Date(2022, time.February, 17, 4, 14, 59, 549000000, time.UTC),
			ActionsExecuted:        "forward",
			RedirectURL:            "-",
			LambdaErrorReason:      "-",
			TargetPortList:         "10.0.4.233:80",
			TargetStatusCodeList:   "200",
			Classification:         "-",
			ClassificationReason:   "-",
		}
		if diff := cmp.Diff(want, le); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("pretty-logentry", func(t *testing.T) {
		le, err := ParseLogEntry(m)
		if err != nil {
			t.Error(err)
		}
		var buf bytes.Buffer
		le.PrettyPrint(&buf)

		const want = `-------------------------------------------------------------------------------
Type                    https
Time                    2022-02-17 04:15:00.493212 +0000 UTC
ELB                     app/something/1234567890abcdef
ClientIP                51.132.188.29
ClientPort              63842
TargetIP                10.0.4.233
TargetPort              80
RequestProcessingTime   0
TargetProcessingTime    0.943
ResponseProcessingTime  0
ELBStatusCode           200
TargetStatusCode        200
ReceivedBytes           404
SentBytes               23441
RequestVerb             GET
RequestURL              https://i.example.com:443/unsafe/260x0/filters:no_upscale():format(jpg):fill(fff,1)/foo.png
RequestProto            HTTP/1.1
UserAgent               Amazon CloudFront
SSLCipher               ECDHE-RSA-AES128-GCM-SHA256
SSLProtocol             TLSv1.2
TargetGroupArn          arn:aws:elasticloadbalancing:eu-central-1:999111222333:targetgroup/something/19328f2048294729
TraceID                 Root=1-620dcbc3-3b4ee4173222f4310fb3c6ec
DomainName              i.example.com
ChosenCertArn           session-reused
MatchedRulePriority     0
RequestCreationTime     2022-02-17 04:14:59.549 +0000 UTC
ActionsExecuted         forward
RedirectURL             -
LambdaErrorReason       -
TargetPortList          10.0.4.233:80
TargetStatusCodeList    200
Classification          -
ClassificationReason    -
`
		got := buf.String()
		t.Log(got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	if err := ms.Err(); err != nil {
		t.Error(err)
	}
}

func mustUncompress(t testing.TB, data []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
		return nil
	}
	res, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	return res
}
