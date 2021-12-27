package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	zip "github.com/hillu/local-log4j-vuln-scanner/appendedzip"
	detectorFilter "github.com/hillu/local-log4j-vuln-scanner/filter"
)

var logFile = os.Stdout
var errFile = os.Stderr

func handleJar(path string, ra io.ReaderAt, sz int64) {
	if verbose {
		_, _ = fmt.Fprintf(logFile, "Inspecting %s...\n", path)
	}
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		_, _ = fmt.Fprintf(logFile, "cant't open JAR file: %s (size %d): %v\n", path, sz, err)
		return
	}
	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".jar", ".war", ".ear":
			fr, err := file.Open()
			if err != nil {
				_, _ = fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			buf, err := ioutil.ReadAll(fr)
			_ = fr.Close()
			if err != nil {
				_, _ = fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", path, file.Name, err)
			}
			handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)))
		default:
			fr, err := file.Open()
			if err != nil {
				_, _ = fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}

			// Identify class files by magic bytes
			buf := bytes.NewBuffer(nil)
			if _, err := io.CopyN(buf, fr, 4); err != nil {
				if err != io.EOF && !quiet {
					_, _ = fmt.Fprintf(logFile, "can't read magic from JAR file member: %s (%s): %v\n", path, file.Name, err)
				}
				_ = fr.Close()
				continue
			} else if !bytes.Equal(buf.Bytes(), []byte{0xca, 0xfe, 0xba, 0xbe}) {
				_ = fr.Close()
				continue
			}
			_, err = io.Copy(buf, fr)
			_ = fr.Close()
			if err != nil {
				_, _ = fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			if desc := detectorFilter.IsVulnerableClass(buf.Bytes(), file.Name, !ignoreV1); desc != "" {
				_, _ = fmt.Fprintf(logFile, "indicator for vulnerable component found in %s (%s): %s\n", path, file.Name, desc)
				continue
			}
		}
	}
}

type excludeFlags []string

func (flags *excludeFlags) String() string {
	return fmt.Sprint(*flags)
}

func (flags *excludeFlags) Set(value string) error {
	*flags = append(*flags, filepath.Clean(value))
	return nil
}

func (flags excludeFlags) Has(path string) bool {
	for _, exclude := range flags {
		if path == exclude {
			return true
		}
	}
	return false
}

var excludes excludeFlags
var verbose bool
var logFileName string
var quiet bool
var ignoreV1 bool

func main() {
	flag.Var(&excludes, "exclude", "paths to exclude (can be used multiple times)")
	flag.BoolVar(&verbose, "verbose", false, "log every archive file considered")
	flag.StringVar(&logFileName, "log", "", "log file to write output to")
	flag.BoolVar(&quiet, "quiet", false, "no output unless vulnerable")
	flag.BoolVar(&ignoreV1, "ignore-v1", false, "ignore log4j 1.x versions")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		_, _ = fmt.Fprint(flag.CommandLine.Output(), "  PATH [, PATH ...]\n        paths to search for Java code\n")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if !quiet {
		fmt.Printf("%s - a simple local log4j vulnerability scanner\n\n", filepath.Base(os.Args[0]))
	}

	if logFileName != "" {
		f, err := os.Create(logFileName)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Could not create log file")
			os.Exit(2)
		}
		logFile = f
		errFile = f
		defer f.Close()
	}

	for _, root := range args {
		_ = filepath.Walk(filepath.Clean(root), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				_, _ = fmt.Fprintf(errFile, "%s: %s\n", path, err)
				return nil
			}
			if excludes.Has(path) {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear":
				f, err := os.Open(path)
				if err != nil {
					_, _ = fmt.Fprintf(errFile, "can't open %s: %v\n", path, err)
					return nil
				}
				defer f.Close()
				sz, err := f.Seek(0, io.SeekEnd)
				if err != nil {
					_, _ = fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					_, _ = fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				handleJar(path, f, sz)
			default:
				return nil
			}
			return nil
		})
	}

	if !quiet {
		fmt.Println("\nScan finished")
	}
}
