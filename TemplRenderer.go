package gofr

import (
	"context"
	"fmt"
	"github.com/a-h/templ"
	"net/http"
)

type TemplRenderer struct {
	Component templ.Component
	Context   context.Context
}

func (tr TemplRenderer) Render(response http.ResponseWriter) error {
	err := tr.Component.Render(tr.Context, response)
	if err != nil {
		return fmt.Errorf("cannot render template: %w", err)
	}
	return nil
}
func (tr TemplRenderer) WriteContentType(response http.ResponseWriter) {
	response.Header().Add("Content-Type", "text/html; charset=utf-8")
}
