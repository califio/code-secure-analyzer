package test

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"os"
	"testing"
)

func TestTable(t *testing.T) {
	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetStyle(table.StyleLight)
	tbl.Style().Options.SeparateRows = true
	tbl.AppendRow(table.Row{"Repo", "http://gitlab.com"})
	tbl.AppendRow(table.Row{"Commit", "1234"})
	tbl.Render()
}
