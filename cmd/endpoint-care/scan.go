package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/kotoba-lang/endpoint-care/internal/disk"
	"github.com/kotoba-lang/endpoint-care/internal/malware"
	ecnet "github.com/kotoba-lang/endpoint-care/internal/net"
	"github.com/kotoba-lang/endpoint-care/internal/procs"
	"github.com/kotoba-lang/endpoint-care/internal/report"
)

// NIST CSF 2.0 subcategory codes assigned to each report section. All codes
// are validated against the live kotoba.cloud CSF 2.0 catalog; see
// docs/csf2-mapping.md for the capability-by-capability table.
var (
	csfDisk     = []string{"ID.AM-01", "PR.PS-02", "PR.PS-03", "PR.IR-04"}
	csfProcs    = []string{"DE.CM-09", "ID.RA-03", "PR.PS-04"}
	csfNet      = []string{"DE.CM-01", "ID.AM-03"}
	csfMalware  = []string{"ID.RA-03", "DE.AE-02"}
	csfProcFind = []string{"ID.RA-03", "DE.AE-02"}
	csfConnFind = []string{"DE.CM-01", "DE.AE-02"}
	csfHashFind = []string{"ID.RA-03"}
)

// diskData is the JSON shape of the disk section payload.
type diskData struct {
	Volume disk.Volume `json:"volume"`
	Dirs   disk.DirScan `json:"dir_scan"`
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", ".", "directory to scan")
	htmlOut := fs.String("html", "", "also write a single-file HTML report to this file")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	rep := report.New("endpoint-care", Version)
	addDiskSection(rep, *path)
	addProcsSection(rep)
	addNetSection(rep)
	addMalwareSection(rep, *path)
	rep.Finalize()

	data, err := rep.JSON()
	if err != nil {
		fmt.Fprintf(stderr, "endpoint-care: encode report: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", data)
	if *htmlOut != "" {
		if err := report.WriteHTMLFile(*htmlOut, rep); err != nil {
			fmt.Fprintf(stderr, "endpoint-care: write html report: %v\n", err)
			return 1
		}
	}
	return rep.ExitCode()
}

func addDiskSection(rep *report.Report, path string) {
	s := report.Section{CSF: csfDisk}
	vol, volErr := disk.VolumeUsage(path)
	dscan, scanErr := disk.LargestDirs(path, disk.DefaultLimits())

	switch {
	case volErr != nil && scanErr != nil:
		err := errors.Join(volErr, scanErr)
		s.Status = "error"
		s.Measured = false
		s.Note = "volume usage and directory scan both failed: " + err.Error()
		s.Data = report.ErrData(err)
	case volErr != nil:
		s.Status = "error"
		s.Measured = false
		s.Note = "volume usage failed: " + volErr.Error()
		s.Data = diskData{Dirs: dscan}
	case scanErr != nil:
		s.Status = "ok"
		s.Measured = true
		s.Note = "directory scan failed: " + scanErr.Error()
		s.Data = diskData{Volume: vol}
	default:
		s.Status = "ok"
		s.Measured = true
		s.Data = diskData{Volume: vol, Dirs: dscan}
	}
	rep.SetSection("disk", s)
}

func addProcsSection(rep *report.Report) {
	s := report.Section{CSF: csfProcs}
	list, err := procs.List()
	if err != nil {
		if errors.Is(err, procs.ErrUnsupported) {
			s.Status = "unsupported"
			s.Note = err.Error()
			s.Data = report.ErrData(err)
		} else {
			s.Status = "error"
			s.Note = err.Error()
			s.Data = report.ErrData(err)
		}
		rep.SetSection("procs", s)
		return
	}
	s.Status = "ok"
	s.Measured = true
	source := ""
	if len(list) > 0 {
		source = list[0].Source
	}
	for _, p := range list {
		if len(p.Flags) == 0 {
			continue
		}
		s.Findings = append(s.Findings, report.Finding{
			Kind:    "suspicious_process",
			Subject: fmt.Sprintf("pid %d (%s)", p.ID, p.Name),
			Flags:   p.Flags,
			CSF:     csfProcFind,
		})
	}
	s.Data = map[string]any{
		"source":        source,
		"process_count": len(list),
		"processes":     list,
	}
	rep.SetSection("procs", s)
}

func addNetSection(rep *report.Report) {
	s := report.Section{CSF: csfNet}
	res, err := ecnet.Connections()
	if err != nil {
		if errors.Is(err, ecnet.ErrUnsupported) {
			s.Status = "unsupported"
		} else {
			s.Status = "error"
		}
		s.Measured = false
		s.Note = err.Error()
		s.Data = report.ErrData(err)
		rep.SetSection("net", s)
		return
	}
	s.Status = "ok"
	s.Measured = true
	for _, c := range res.Conns {
		if len(c.Flags) == 0 {
			continue
		}
		s.Findings = append(s.Findings, report.Finding{
			Kind:    "suspicious_connection",
			Subject: fmt.Sprintf("%s %s -> %s", c.Proto, c.Local, c.Remote),
			Flags:   c.Flags,
			CSF:     csfConnFind,
		})
	}
	s.Data = map[string]any{
		"source":           res.Source,
		"listener_count":   res.Listeners,
		"connection_count": len(res.Conns),
		"connections":      res.Conns,
	}
	rep.SetSection("net", s)
}

func addMalwareSection(rep *report.Report, path string) {
	s := report.Section{CSF: csfMalware}
	res, err := malware.HashCheck(path, malware.DefaultLimits())
	if err != nil {
		s.Status = "error"
		s.Measured = false
		s.Note = err.Error()
		s.Data = report.ErrData(err)
		rep.SetSection("malware", s)
		return
	}
	s.Status = res.Status
	s.Measured = res.Compared > 0
	s.Note = res.Note
	s.Data = res
	for _, f := range res.Files {
		if !f.Matched {
			continue
		}
		s.Findings = append(s.Findings, report.Finding{
			Kind:    "denylisted_hash",
			Subject: f.Path,
			Flags:   []string{"sha256-match:" + f.SHA256},
			CSF:     csfHashFind,
		})
	}
	rep.SetSection("malware", s)
}
