package client

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
	pb "github.com/ITA-Dnipro/Dp-230-Test-XSS/proto"
)

type ReportClient struct {
	client pb.ReportServiceClient
}

func NewReportClient(conn *grpc.ClientConn) *ReportClient {
	client := pb.NewReportServiceClient(conn)
	return &ReportClient{client: client}
}

func (rs *ReportClient) PushResult(ctx context.Context, id string, tr model.TestResult) error {
	req := &pb.PushResultReq{ID: id, TestResult: TestResultToProto(tr)}
	_, err := rs.client.PushResult(ctx, req)
	return err
}

func TestResultToProto(tr model.TestResult) *pb.TestResult {
	res := &pb.TestResult{
		Type: tr.Type,
	}

	for _, r := range tr.Results {
		res.Results = append(res.Results, ResultToProto(r))
	}

	return res
}

func PocToProto(p model.PoC) *pb.PoC {
	return &pb.PoC{
		Type:       p.Type,
		InjectType: p.InjectType,
		PoCType:    p.PoCType,
		Method:     p.Method,
		Data:       p.Data,
		Param:      p.Param,
		Payload:    p.Payload,
		Evidence:   p.Evidence,
		SWE:        p.CWE,
		Severity:   p.Severity,
	}
}

func ResultToProto(res model.Result) *pb.Result {
	r := &pb.Result{
		URL:       res.URL,
		StartTime: timestamppb.New(res.StartTime),
		EndTime:   timestamppb.New(res.EndTime),
	}

	for _, p := range res.PoCs {
		r.PoCs = append(r.PoCs, PocToProto(p))
	}
	return r
}
