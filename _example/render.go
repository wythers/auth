package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/wythers/auth"
)

var (
	_ auth.Renderer = (*MailRender)(nil)
)

type MailRender struct {
	htmlTemplates map[string]*template.Template
	txtTemplates  map[string]*template.Template
}

func (e *MailRender) Load(templateDir string) error {
	if e.htmlTemplates == nil {
		e.htmlTemplates = make(map[string]*template.Template)
	}
	if e.txtTemplates == nil {
		e.txtTemplates = make(map[string]*template.Template)
	}

	entries, err := os.ReadDir(templateDir)
	if err != nil {
		return fmt.Errorf("failed to read template directory %s: %w", templateDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if !strings.HasSuffix(filename, ".tpl") {
			continue
		}

		templateName := strings.TrimSuffix(filename, ".tpl")
		fullPath := filepath.Join(templateDir, filename)

		content, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read template file %s: %w", fullPath, err)
		}

		if strings.HasSuffix(templateName, "_txt") {
			txt, err := template.New("auth").Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to load txt template for page %s: %w", templateName, err)
			}
			e.txtTemplates[templateName] = txt
		} else {
			html, err := template.New("auth").Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to load html template for page %s: %w", templateName, err)
			}
			e.htmlTemplates[templateName] = html
		}
	}

	return nil
}

// Render a view
func (e *MailRender) Render(ctx context.Context, page string, data auth.HTMLData) (output []byte, contentType string, err error) {
	buf := &bytes.Buffer{}

	var exe *template.Template
	var ok bool
	if strings.HasSuffix(page, "_txt") {
		exe, ok = e.txtTemplates[page]
		contentType = "text/plain"
	} else {
		exe, ok = e.htmlTemplates[page]
		contentType = "text/html"
	}

	if !ok {
		return nil, "", fmt.Errorf("template for page %s not found", page)
	}

	err = exe.Execute(buf, data)
	if err != nil {
		return nil, "", fmt.Errorf("failed to render template for page %s: %w", page, err)
	}

	return buf.Bytes(), contentType, nil
}
