package renderer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/a-h/templ"
)

type Templ struct {
	Component templ.Component
	Context   context.Context
}

func (tr Templ) Render(response http.ResponseWriter) error {
	err := tr.Component.Render(tr.Context, response)
	if err != nil {
		return fmt.Errorf("cannot render template: %w", err)
	}
	return nil
}
func (tr Templ) WriteContentType(response http.ResponseWriter) {
	response.Header().Add("Content-Type", "text/html; charset=utf-8")
}
