package middleware

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/open-policy-agent/opa/rego"
)

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("opa", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Middleware
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return m, err
	})
}

type Middleware struct {
	Policy string `json:"policy"`
	rego   func(*rego.Rego)
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.opa",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	if len(m.Policy) > 0 {
		m.rego = rego.Load([]string{m.Policy}, nil)
	}

	return nil
}

func (m *Middleware) Validate() error {
	return nil
}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := context.TODO()

	input := make(map[string]interface{})
	input["method"] = r.Method
	input["path"] = strings.Split(r.URL.Path[1:], "/")

	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 0 {
		match := regexp.MustCompile(`^Bearer\s+(\S+)$`).FindStringSubmatch(authHeader)
		if len(match) > 0 {
			input["identity"] = match[1]
		}
	}

	target, err := rego.New(rego.Query("data.system.authz.allow"), m.rego).PrepareForEval(ctx)
	if err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}

	result, err := target.Eval(ctx, rego.EvalInput(input))
	if err != nil || len(result) == 0 || !result.Allowed() {
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}

	err = next.ServeHTTP(w, r)
	if err != nil {
		return err
	}

	return nil
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	args := d.RemainingArgs()

	if len(args) == 1 {
		d.NextArg()
		m.Policy = d.Val()
	}

	return nil
}
