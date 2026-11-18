package utils

import (
	"errors"
	"html/template"
	"text/template/parse"
)

const BackendUnavailablePageMaxBytes = 60 * 1024

type BackendUnavailablePageData struct {
	SAMWAF_HOST        string
	SAMWAF_STATUS_CODE string
}

// ParseBackendUnavailablePage accepts literal HTML and the two documented placeholders.
func ParseBackendUnavailablePage(content string) (*template.Template, error) {
	tmpl, err := template.New("backendUnavailable").Delims("[[", "]]").Parse(content)
	if err != nil {
		return nil, err
	}
	invalid := errors.New("unsupported page placeholder")
	if len(tmpl.Templates()) != 1 || tmpl.Tree == nil || tmpl.Tree.Root == nil {
		return nil, invalid
	}
	for _, node := range tmpl.Tree.Root.Nodes {
		switch node := node.(type) {
		case *parse.TextNode, *parse.CommentNode:
		case *parse.ActionNode:
			pipe := node.Pipe
			if len(pipe.Decl) != 0 || len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
				return nil, invalid
			}
			field, ok := pipe.Cmds[0].Args[0].(*parse.FieldNode)
			if !ok || len(field.Ident) != 1 || (field.Ident[0] != "SAMWAF_HOST" && field.Ident[0] != "SAMWAF_STATUS_CODE") {
				return nil, invalid
			}
		default:
			return nil, invalid
		}
	}
	return tmpl, nil
}
