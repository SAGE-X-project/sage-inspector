// Command adk-source-inventory parses a bounded list of Go files without loading
// dependencies or executing the inspected program. Calls are syntax, not edges
// proven reachable at runtime; arguments and literal values are never exported.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxFile = 2 << 20
const maxList = 512 << 10

type call struct {
	Callee string `json:"callee"`
	Line   int    `json:"line"`
}
type declaration struct {
	Name     string `json:"name"`
	Exported bool   `json:"exported"`
	Line     int    `json:"line"`
	EndLine  int    `json:"end_line"`
	Calls    []call `json:"calls"`
}
type source struct {
	Path             string        `json:"path"`
	SHA256           string        `json:"sha256"`
	Package          string        `json:"package"`
	Declarations     []declaration `json:"declarations"`
	InitializerCalls []call        `json:"initializer_calls"`
}
type inventory struct {
	SchemaVersion int      `json:"schema_version"`
	Kind          string   `json:"kind"`
	Files         []source `json:"files"`
}

// expression deliberately omits literal values, arguments and function bodies.
func expression(e ast.Expr) string {
	switch n := e.(type) {
	case *ast.Ident:
		return n.Name
	case *ast.SelectorExpr:
		return expression(n.X) + "." + n.Sel.Name
	case *ast.StarExpr:
		return "*" + expression(n.X)
	case *ast.ParenExpr:
		return "(" + expression(n.X) + ")"
	case *ast.CallExpr:
		return expression(n.Fun) + "()"
	case *ast.IndexExpr:
		return expression(n.X) + "[]"
	case *ast.IndexListExpr:
		return expression(n.X) + "[]"
	case *ast.FuncLit:
		return "<function-literal>"
	default:
		return fmt.Sprintf("<%T>", e)
	}
}
func receiver(e ast.Expr) string {
	switch n := e.(type) {
	case *ast.StarExpr:
		return receiver(n.X)
	case *ast.IndexExpr:
		return receiver(n.X)
	case *ast.IndexListExpr:
		return receiver(n.X)
	default:
		return expression(e)
	}
}
func calls(n ast.Node, fset *token.FileSet) []call {
	result := []call{}
	if n != nil {
		ast.Inspect(n, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				result = append(result, call{expression(c.Fun), fset.Position(c.Pos()).Line})
			}
			return true
		})
	}
	return result
}
func readSource(root, name string) ([]byte, error) {
	if !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.Contains(name, "\\") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
		return nil, errors.New("invalid production source path")
	}
	path := root
	parts := strings.Split(name, "/")
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) || (i == len(parts)-1 && (!info.Mode().IsRegular() || info.Size() > maxFile)) {
			return nil, errors.New("source must be a bounded regular file without symlinks")
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(data) > maxFile {
		return nil, errors.New("source read failed or exceeded limit")
	}
	return data, nil
}
func inspect(root string, input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, maxList+1))
	if err != nil || len(raw) > maxList {
		return errors.New("file list exceeds limit")
	}
	var names []string
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err = decoder.Decode(&names); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing file list data")
	}
	if len(names) == 0 || len(names) > 512 {
		return errors.New("file count out of bounds")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.IsDir() {
		return errors.New("source root is unavailable")
	}
	result := inventory{1, "GO_SYNTAX_INVENTORY", []source{}}
	for i, name := range names {
		if i > 0 && names[i-1] >= name {
			return errors.New("file list must be sorted and unique")
		}
		data, err := readSource(absolute, name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fset := token.NewFileSet()
		tree, err := parser.ParseFile(fset, name, data, parser.AllErrors)
		if err != nil {
			return fmt.Errorf("%s: syntax invalid", name)
		}
		hash := sha256.Sum256(data)
		item := source{name, hex.EncodeToString(hash[:]), tree.Name.Name, []declaration{}, []call{}}
		for _, d := range tree.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				name := fn.Name.Name
				if fn.Recv != nil {
					name = receiver(fn.Recv.List[0].Type) + "." + name
				}
				item.Declarations = append(item.Declarations, declaration{name, fn.Name.IsExported(), fset.Position(fn.Pos()).Line, fset.Position(fn.End()).Line, calls(fn, fset)})
			} else {
				item.InitializerCalls = append(item.InitializerCalls, calls(d, fset)...)
			}
		}
		result.Files = append(result.Files, item)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
func main() {
	root := flag.String("root", "", "root of inspected source; JSON paths read from stdin")
	flag.Parse()
	if *root == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "root required; no positional arguments")
		os.Exit(2)
	}
	if err := inspect(*root, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
