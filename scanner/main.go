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
	"time"

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
				logInaccessible("can't open JAR file member for reading", path+"/"+file.Name, err)
				continue
			}
			buf, err := ioutil.ReadAll(fr)
			_ = fr.Close()
			if err != nil {
				logInaccessible("can't read JAR file member", path+"/"+file.Name, err)
			}
			handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)))
		default:
			fr, err := file.Open()
			if err != nil {
				logInaccessible("can't open JAR file member for reading", path+"/"+file.Name, err)
				continue
			}

			// Identify class files by magic bytes
			buf := bytes.NewBuffer(nil)
			if _, err := io.CopyN(buf, fr, 4); err != nil {
				if err != io.EOF && !quiet {
					logInaccessible("can't read magic from JAR file member", path+"/"+file.Name, err)
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
				logInaccessible("can't read JAR file member", path+"/"+file.Name, err)
				continue
			}

			incrementProgress(path, file.Name)

			if desc := detectorFilter.IsVulnerableClass(buf.Bytes(), file.Name, !ignoreV1); desc != "" {
				countMatched++
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
var reportInaccessible bool

var startAll, startRoot, lastStepStart int64
var countScanned, countMatched, progressInterval int

func main() {
	flag.Var(&excludes, "exclude", "paths to exclude (can be used multiple times)")
	flag.BoolVar(&reportInaccessible, "report-inaccessible", false, "report inaccessible files")
	flag.BoolVar(&verbose, "verbose", false, "log every archive file considered")
	flag.StringVar(&logFileName, "log", "", "log file to write output to")
	flag.BoolVar(&quiet, "quiet", false, "no output unless vulnerable")
	flag.BoolVar(&ignoreV1, "ignore-v1", false, "ignore log4j 1.x versions")
	flag.IntVar(&progressInterval, "progress-interval", 100000, "progress report interval")
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

	startAll = time.Now().UnixMilli()
	lastStepStart = startAll
	countScanned = 0
	countMatched = 0

	for _, root := range args {
		startRoot = time.Now().UnixMilli()
		cleanPath := filepath.Clean(root)
		_ = filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				logInaccessible("can't access", path, err)
				return nil
			}
			if excludes.Has(path) {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			incrementProgress(path)

			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear", ".zip":
				f, err := os.Open(path)
				if err != nil {
					logInaccessible("can't open", path, err)
					return nil
				}
				defer f.Close()
				sz, err := f.Seek(0, io.SeekEnd)
				if err != nil {
					logInaccessible("can't seek in", path, err)
					return nil
				}
				handleJar(path, f, sz)
			default:
				return nil
			}
			return nil
		})
		logInfo(fmt.Sprintf("Scanned %s in %v", cleanPath, time.Now().UnixMilli()-startRoot))
	}

	if !quiet {
		fmt.Printf("\nScan finished in %v ms\n", time.Now().UnixMilli()-startAll)
	}
}

func logInaccessible(message string, s string, err error) {
	if reportInaccessible {
		_, _ = fmt.Fprintf(errFile, "ERROR\t"+message+" %s: %v\n", s, err)
	}
}

func currentTimeStr() string {
	return time.Now().Format("15:04:05")
}

func logInfo(message string) {
	_, _ = fmt.Fprintf(logFile, "%s INFO\t%s\n", currentTimeStr(), message)
}

func incrementProgress(path ...string) {
	countScanned++
	if countScanned%progressInterval == 0 {
		var now = time.Now().UnixMilli()
		var curStepDuration = now - lastStepStart
		lastStepStart = now
		logInfo(fmt.Sprintf("Done %v, found %v, %v per %v, cur %s", formatCount(countScanned),
			formatCount(countMatched), formatDuration(curStepDuration),
			formatCount(progressInterval), fmt.Sprint(path)))
	}
}
