package app

import (
	"errors"

	"netlens/internal/capture"
)

type BodyInput struct {
	ID     string `json:"id"`
	Side   string `json:"side,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// Body 是显式的完整正文读取入口，普通详情、HAR 与日志也返回真实值，正文预览受展示限额约束。
func (s *Service) Body(in BodyInput) (any, error) {
	if in.ID == "" {
		return nil, errors.New("id is required")
	}
	if in.Side == "" {
		in.Side = "response"
	}
	if in.Side != "request" && in.Side != "response" {
		return nil, errors.New("side must be request or response")
	}
	if in.Limit == 0 {
		in.Limit = 16384
	}
	f, ok := s.Store.Get(in.ID)
	if !ok {
		return nil, errors.New("flow not found (it may have been evicted)")
	}
	if !f.RawAvailable {
		return nil, errors.New("raw body unavailable for this flow; encrypted tunnels have no captured application body")
	}
	body, headers := f.ResponseBody, f.ResponseHeaders
	if in.Side == "request" {
		body, headers = f.RequestBody, f.RequestHeaders
	}
	v, err := capture.InspectBody(body, headers).Page(in.Offset, in.Limit)
	if err != nil {
		return nil, err
	}
	v["id"], v["side"], v["completed"] = f.ID, in.Side, f.Completed
	return v, nil
}
