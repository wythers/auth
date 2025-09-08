package auth

import "context"

type HTMLData map[string]any

type Renderer interface {
	// Load the given templates, will most likely be called multiple times
	Load(templateDir string) error

	// Render the given template
	Render(ctx context.Context, page string, data HTMLData) (output []byte, contentType string, err error)
}
