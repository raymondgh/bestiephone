package chi

import (
	"context"
	"net/http"
	"strings"
)

type Middleware func(http.Handler) http.Handler

type Router interface {
	http.Handler
	Use(middlewares ...Middleware)
	Method(method, pattern string, handler http.HandlerFunc)
	Get(pattern string, handler http.HandlerFunc)
	Post(pattern string, handler http.HandlerFunc)
	Route(pattern string, fn func(r Router))
}

type Mux struct {
	base        string
	routes      []route
	middlewares []Middleware
}

type route struct {
	method   string
	segments []segment
	handler  http.Handler
}

type segment struct {
	literal bool
	value   string
}

type paramsKeyType struct{}

var paramsKey paramsKeyType

func NewRouter() *Mux {
	return &Mux{base: "/"}
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := normalizePath(r.URL.Path)
	segments := splitPath(path)
	for _, rt := range m.routes {
		if rt.method != "" && r.Method != rt.method {
			continue
		}
		if len(rt.segments) != len(segments) {
			continue
		}
		params := map[string]string{}
		matched := true
		for idx, seg := range rt.segments {
			if seg.literal {
				if seg.value != segments[idx] {
					matched = false
					break
				}
				continue
			}
			params[seg.value] = segments[idx]
		}
		if !matched {
			continue
		}
		if len(params) > 0 {
			ctx := context.WithValue(r.Context(), paramsKey, params)
			r = r.WithContext(ctx)
		}
		rt.handler.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (m *Mux) Use(middlewares ...Middleware) {
	m.middlewares = append(m.middlewares, middlewares...)
}

func (m *Mux) Method(method, pattern string, handler http.HandlerFunc) {
	if handler == nil {
		return
	}
	fullPath := joinPaths(m.base, pattern)
	rt := route{
		method:   strings.ToUpper(method),
		segments: parsePattern(fullPath),
		handler:  m.wrapMiddlewares(handler),
	}
	m.routes = append(m.routes, rt)
}

func (m *Mux) Get(pattern string, handler http.HandlerFunc) {
	m.Method(http.MethodGet, pattern, handler)
}

func (m *Mux) Post(pattern string, handler http.HandlerFunc) {
	m.Method(http.MethodPost, pattern, handler)
}

func (m *Mux) Route(pattern string, fn func(r Router)) {
	if fn == nil {
		return
	}
	sub := &Mux{
		base:        joinPaths(m.base, pattern),
		middlewares: append([]Middleware{}, m.middlewares...),
	}
	fn(sub)
	m.routes = append(m.routes, sub.routes...)
}

func (m *Mux) wrapMiddlewares(handler http.HandlerFunc) http.Handler {
	h := http.Handler(handler)
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		h = m.middlewares[i](h)
	}
	return h
}

func parsePattern(pattern string) []segment {
	normalized := normalizePath(pattern)
	parts := splitPath(normalized)
	if len(parts) == 0 {
		return []segment{}
	}
	segments := make([]segment, 0, len(parts))
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			segments = append(segments, segment{literal: false, value: name})
			continue
		}
		segments = append(segments, segment{literal: true, value: part})
	}
	return segments
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "" {
		return "/"
	}
	return path
}

func joinPaths(base, path string) string {
	if base == "" {
		base = "/"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	if path == "" || path == "/" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if base == "/" {
		return normalizePath(path)
	}
	combined := base + path
	return normalizePath(combined)
}

func URLParam(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	if values, ok := r.Context().Value(paramsKey).(map[string]string); ok {
		return values[key]
	}
	return ""
}
