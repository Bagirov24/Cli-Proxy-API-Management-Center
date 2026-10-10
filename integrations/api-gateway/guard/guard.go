package cpaguard

import (
 "net/http"
 "github.com/Bagirov24/Cli-Proxy-API-Management-Center/integrations/api-gateway/guard/policy"
 "github.com/caddyserver/caddy/v2"
 "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
 "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
 "github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
 caddy.RegisterModule(Guard{})
 httpcaddyfile.RegisterHandlerDirective("cpa_key_guard", parseCaddyfile)
 httpcaddyfile.RegisterDirectiveOrder("cpa_key_guard", "before", "reverse_proxy")
}

type Guard struct{}
func (Guard) CaddyModule() caddy.ModuleInfo {
 return caddy.ModuleInfo{ID:"http.handlers.cpa_key_guard",New:func() caddy.Module {return new(Guard)}}
}
func (Guard) ServeHTTP(w http.ResponseWriter,r *http.Request,next caddyhttp.Handler) error {
 if !policy.Accept(r) {
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("Content-Type","application/json")
  w.WriteHeader(http.StatusUnauthorized)
  _,_ = w.Write([]byte(`{"error":{"message":"Unauthorized","type":"authentication_error"}}`))
  return nil
 }
 return next.ServeHTTP(w,r)
}
func (Guard) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
 for d.Next() {
  if d.NextArg() || d.NextBlock(0) {return d.Err("cpa_key_guard does not accept arguments or blocks")}
 }
 return nil
}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler,error) {
 g:=new(Guard)
 if err:=g.UnmarshalCaddyfile(h.Dispenser);err!=nil{return nil,err}
 return g,nil
}
var _ caddy.Module = (*Guard)(nil)
var _ caddyfile.Unmarshaler = (*Guard)(nil)
var _ caddyhttp.MiddlewareHandler = (*Guard)(nil)
