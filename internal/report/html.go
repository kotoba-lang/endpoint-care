package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
)

// funcMap is registered BEFORE parsing: text/template resolves function
// names at Parse time, so registering afterwards panics at package init.
var funcMap = template.FuncMap{
	"join": func(ss []string, sep string) string { return strings.Join(ss, sep) },
	"json": func(v any) string {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Sprintf("unrenderable: %v", err)
		}
		return string(b)
	},
}

var htmlTmpl = template.Must(template.New("report").Funcs(funcMap).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Tool.Name}} report — {{.GeneratedAt}}</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;padding:2rem;color:#111;background:#fafafa}
 h1{font-size:1.3rem;margin:0 0 .25rem}
 .meta{color:#666;font-size:.85rem;margin-bottom:1.5rem}
 section{background:#fff;border:1px solid #e2e2e2;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem}
 h2{font-size:1.05rem;margin:0 0 .5rem;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
 .chip{font-size:.7rem;border:1px solid #ccc;border-radius:999px;padding:.1rem .55rem;color:#555}
 .chip.ok{border-color:#2c2;background:#efe;color:#171}
 .chip.error,.chip.unsupported,.chip.unavailable{border-color:#c33;background:#fee;color:#922}
 .chip.refused{border-color:#c33;background:#fcc;color:#800;font-weight:bold}
 .csf{font-size:.75rem;color:#777}
 .note{font-size:.85rem;color:#777}
 .bar{display:flex;align-items:center;gap:.5rem;font-size:.8rem;margin:.15rem 0}
 .bar .label{width:45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .bar .track{flex:1;background:#eee;border-radius:4px;height:10px}
 .bar .fill{background:#4a6fd8;height:10px;border-radius:4px}
 .bar .val{width:6rem;text-align:right;color:#555}
 .finding{font-size:.85rem;color:#922;padding:.15rem 0;border-top:1px dashed #eee}
 pre{background:#f6f6f6;padding:.75rem;border-radius:6px;overflow:auto;font-size:.75rem;max-height:22rem}
</style>
</head>
<body>
<h1>{{.Tool.Name}} {{.Tool.Version}} — report</h1>
<div class="meta">{{.Hostname}} · {{.OS}}/{{.Arch}} · {{.GeneratedAt}} · schema {{.SchemaVersion}}</div>
{{range $name, $s := .Sections}}
<section>
 <h2>{{$name}} <span class="chip {{$s.Status}}">{{$s.Status}}</span>
 {{if $s.Measured}}<span class="chip ok">measured</span>{{else}}<span class="chip">not measured</span>{{end}}
 <span class="csf">{{join $s.CSF " · "}}</span></h2>
 {{if $s.Note}}<div class="note">{{$s.Note}}</div>{{end}}
 {{if eq $name "disk"}}{{range $.DirBars}}<div class="bar"><span class="label">{{.Path}}</span><span class="track"><span class="fill" style="width:{{.Pct}}%"></span></span><span class="val">{{.Human}}</span></div>{{end}}{{end}}
 {{range $s.Findings}}<div class="finding">&#9888; {{.Kind}}: {{.Subject}} ({{join .Flags ", "}})</div>{{end}}
 {{if $s.Data}}<pre>{{json $s.Data}}</pre>{{end}}
</section>
{{end}}
</body>
</html>`))

// DirBar is one rendered row of the disk chart.
type DirBar struct {
	Path  string
	Pct   int
	Human string
}

type tmplData struct {
	*Report
	DirBars []DirBar
}

// dirBars extracts the disk section's top directories for the bar chart.
// Missing or reshaped data simply yields no bars — the raw JSON below the
// chart still carries everything.
func (r *Report) dirBars() []DirBar {
	s, ok := r.Sections["disk"]
	if !ok || s.Data == nil {
		return nil
	}
	raw, err := json.Marshal(s.Data)
	if err != nil {
		return nil
	}
	var wrap struct {
		DirScan struct {
			Dirs []struct {
				Path      string `json:"path"`
				SizeBytes uint64 `json:"size_bytes"`
			} `json:"dirs"`
		} `json:"dir_scan"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil
	}
	sort.Slice(wrap.DirScan.Dirs, func(i, j int) bool {
		return wrap.DirScan.Dirs[i].SizeBytes > wrap.DirScan.Dirs[j].SizeBytes
	})
	var max uint64
	for _, d := range wrap.DirScan.Dirs {
		if d.SizeBytes > max {
			max = d.SizeBytes
		}
	}
	if max == 0 {
		return nil
	}
	bars := make([]DirBar, 0, len(wrap.DirScan.Dirs))
	for _, d := range wrap.DirScan.Dirs {
		bars = append(bars, DirBar{
			Path:  d.Path,
			Pct:   int(float64(d.SizeBytes) * 100 / float64(max)),
			Human: humanBytes(d.SizeBytes),
		})
	}
	return bars
}

// WriteHTMLFile renders the single-file HTML report to path.
func WriteHTMLFile(path string, r *Report) error {
	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, tmplData{Report: r, DirBars: r.dirBars()}); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// humanBytes formats a byte count with binary units (report-local copy so the
// HTML path does not depend on the disk package).
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}[exp])
}
