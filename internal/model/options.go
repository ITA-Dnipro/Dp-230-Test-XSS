package model

import (
	"sync"
	t "time"
)

type Options struct {
	Cookie           string   `json:"cookie"`
	Header           []string `json:"header"`
	CustomAlertValue string   `json:"custom-alert-value"`
	CustomAlertType  string   `json:"custom-alert-type"`
	Data             string   `json:"data"`
	UserAgent        string   `json:"user-agent"`
	Format           string   `json:"format"`
	ProxyAddress     string   `json:"proxy"`
	Timeout          int      `json:"timeout"`
	Concurrence      int      `json:"worker"`
	Delay            int      `json:"delay"`
	MulticastMode    bool
	Mining           bool   `json:"mining-dict"`
	FindingDOM       bool   `json:"mining-dom"`
	Method           string `json:"method"`
	CookieFromRaw    string
	StartTime        t.Time
	PathReflection   map[int]string
	UseHeadless      bool `json:"use-headless"`
	UseDeepDXSS      bool `json:"use-deepdxss"`
	Mutex            *sync.Mutex
}

// MassJob is list for mass
type MassJob struct {
	Name string
	URLs []string
}

// Issue is struct of issue
type Issue struct {
	Type  string `json:"type"`
	Param string `json:"param"`
	PoC   PoC    `json:"poc"`
}
