package middleware

import (
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

var bearer = regexp.MustCompile(`^Bearer\s+(\S+)$`)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("opa", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Middleware
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return m, err
	})
}

type Middleware struct {
	Bundle   string `json:"bundle"`
	prepared rego.PreparedEvalQuery
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.opa",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(ctx caddy.Context) (err error) {
	m.prepared, err = rego.New(rego.Query("data.system.authz.allow"), rego.LoadBundle(m.Bundle)).PrepareForEval(ctx)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	return nil
}

func (m *Middleware) Validate() (err error) {
	return nil
}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	input := make(map[string]interface{})
	input["method"] = r.Method
	input["path"] = strings.Split(r.URL.Path[1:], "/")

	authHeader := r.Header.Get("X-Auth-Bearer")
	if len(authHeader) > 0 {
		input["identity"] = authHeader
	}

	result, err := m.prepared.Eval(r.Context(), rego.EvalInput(input))
	if err != nil || len(result) == 0 || !result.Allowed() {
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}

	err = next.ServeHTTP(w, r)
	if err != nil {
		return err
	}

	return nil
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	d.Next()

	for i := d.Nesting(); d.NextBlock(i); {
		token := d.Val()
		switch token {
		case "bundle":
			if !d.NextArg() {
				return d.Err("Missing policy bundle")
			}

			m.Bundle = d.Val()

			if d.NextArg() {
				return d.ArgErr()
			}

			return nil
		default:
			return d.Errf("unrecognized subdirective: '%s'", token)
		}
	}

	return nil
}
