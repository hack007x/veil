package engine

import (
	"time"

	"github.com/hack007x/veil/internal/oob"
	"github.com/hack007x/veil/internal/runner"
	tpl "github.com/hack007x/veil/template"
)

const defaultVersion = "1.0.0"

// DefaultEngine is the built-in full-featured scanning engine.
type DefaultEngine struct {
	oobMgr *oob.Manager
}

func newDefaultEngine() *DefaultEngine {
	return &DefaultEngine{}
}

func (e *DefaultEngine) Name() string    { return "veil-default" }
func (e *DefaultEngine) Version() string { return defaultVersion }

// InitOOB initialises the OOB callback manager.
func (e *DefaultEngine) InitOOB(verbose bool) {
	e.oobMgr = oob.NewManager(verbose)
}

// OOBAvailable reports whether an OOB provider connected successfully.
func (e *DefaultEngine) OOBAvailable() bool {
	return e.oobMgr != nil && e.oobMgr.Available()
}

// OOBProviderName returns the name of the active OOB provider.
func (e *DefaultEngine) OOBProviderName() string {
	if e.oobMgr == nil {
		return ""
	}
	return e.oobMgr.ProviderName()
}

func (e *DefaultEngine) Scan(t *tpl.PocTemplate, target string, opts ScanOptions) *tpl.ScanResult {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	runnerOpts := runner.Options{
		Timeout:         time.Duration(timeout) * time.Second,
		FollowRedirects: opts.FollowRedirects,
		VerifySSL:       opts.VerifySSL,
		Proxy:           opts.Proxy,
		Verbose:         opts.Verbose,
		OOBManager:      e.oobMgr,
	}
	r := runner.New(runnerOpts)
	return r.Run(t, target)
}
