package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/google/certificate-transparency-go"
	ct_tls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/publicsuffix"
)

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

const MaxDownloadRetries = 10

const ChromeLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

type ChromeLogs struct {
	Version          string    `json:"version,omitempty"`
	LogListTimestamp time.Time `json:"log_list_timestamp,omitempty"`
	Operators        []struct {
		Name  string   `json:"name,omitempty"`
		Email []string `json:"email,omitempty"`
		Logs  []struct {
			Description string `json:"description,omitempty"`
			LogID       string `json:"log_id,omitempty"`
			Key         string `json:"key,omitempty"`
			URL         string `json:"url,omitempty"`
			Mmd         int    `json:"mmd,omitempty"`
			State       struct {
				Usable struct {
					Timestamp time.Time `json:"timestamp,omitempty"`
				} `json:"usable,omitempty"`
			} `json:"state,omitempty"`
			TemporalInterval struct {
				StartInclusive time.Time `json:"start_inclusive,omitempty"`
				EndExclusive   time.Time `json:"end_exclusive,omitempty"`
			} `json:"temporal_interval,omitempty"`
		} `json:"logs,omitempty"`
		TiledLogs []any `json:"tiled_logs,omitempty"`
	} `json:"operators,omitempty"`
}

type CTResult struct {
	Name   string   `json:"name"`
	TS     uint64   `json:"ts"`
	CN     string   `json:"cn"`
	SHA1   string   `json:"sha1"`
	Emails []string `json:"email,omitempty"`
	IPs    []string `json:"ip,omitempty"`
	DNS    []string `json:"dns,omitempty"`
}

var statOutput atomic.Int64
var statInput atomic.Int64
var optLogURL *string
var optTailCount *int
var optPollTime *int
var optFollow *bool
var optPattern *string
var optPatternCompiled *regexp.Regexp

var wd sync.WaitGroup
var wi sync.WaitGroup
var wo sync.WaitGroup

type CTEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type CTEntries struct {
	Entries []CTEntry `json:"entries"`
}

type CTEntriesError struct {
	ErrorMessage string `json:"error_message"`
	Success      bool   `json:"success"`
}

type CTHead struct {
	TreeSize          int64  `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Synchronizes data from one or more CT logs and extract hostnames")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func scrubX509Value(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.ReplaceAll(s, "\x00", "")
}

func downloadJSON(url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, nil, err
	}

	req.Header.Set("Accept", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, resp, err
	}

	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, resp, err
	}

	return content, resp, err
}

func downloadSTH(logURL string) (CTHead, error) {
	retries := 0
	var sth CTHead
	url := fmt.Sprintf("%s/ct/v1/get-sth", strings.TrimSuffix(logURL, "/"))

RetryDownload:
	data, resp, err := downloadJSON(url)
	if err != nil {
		return sth, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		if retries < MaxDownloadRetries {
			retries++
			fmt.Fprintf(os.Stderr, "[*] Sleeping for %d seconds (%s) due to status %s\n", *optPollTime, logURL, resp.Status)
			time.Sleep(time.Duration(*optPollTime) * time.Second)
			goto RetryDownload
		}
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 600 {
		return sth, fmt.Errorf("status code %d (%s)", resp.StatusCode, resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		return sth, fmt.Errorf("unexpected status code %d from %s (%v)", resp.StatusCode, url, resp)
	}

	err = json.Unmarshal(data, &sth)
	return sth, err
}

func downloadEntries(logURL string, startIdx int64, stopIdx int64) (CTEntries, error) {
	retries := 0
	var entries CTEntries
	var entriesErr CTEntriesError

	url := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", strings.TrimSuffix(logURL, "/"), startIdx, stopIdx)
RetryDownload:
	data, resp, err := downloadJSON(url)
	if err != nil {
		return entries, err
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout {
		if retries < MaxDownloadRetries {
			retries++
			fmt.Fprintf(os.Stderr, "[*] Sleeping for %d seconds (%s) due to status %s\n", *optPollTime, logURL, resp.Status)
			time.Sleep(time.Duration(*optPollTime) * time.Second)
			goto RetryDownload
		}
	}
	if resp.StatusCode != http.StatusOK {
		return entries, fmt.Errorf("unexpected status code %d from %s (%v)", resp.StatusCode, url, resp)
	}

	if strings.Contains(string(data), "\"error_message\":") {
		err = json.Unmarshal(data, &entriesErr)
		if err != nil {
			return entries, err
		}
		return entries, errors.New(entriesErr.ErrorMessage)
	}

	err = json.Unmarshal(data, &entries)
	if err != nil {
		trimmedData := string(data)
		if len(trimmedData) > 100 {
			trimmedData = trimmedData[:100] + "..."
		}
		err = fmt.Errorf("decode error: %w (%s)", err, trimmedData)
	}
	return entries, err
}

func downloadLog(logURL string, cInp chan<- *CTEntry) {
	var iteration int64 = 0
	var curIdx int64 = 0

	defer wd.Done()

	for {
		if iteration > 0 {
			fmt.Fprintf(os.Stderr, "[*] Sleeping for %d seconds (%s) at index %d\n", *optPollTime, logURL, curIdx)
			time.Sleep(time.Duration(*optPollTime) * time.Second)
		}

		sth, sthErr := downloadSTH(logURL)
		if sthErr != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to download STH for %s: %s (skipping)\n", logURL, sthErr)
			return
		}

		var startIdx int64 = 0

		if iteration == 0 {
			startIdx = sth.TreeSize - int64(*optTailCount)
			if startIdx < 0 {
				startIdx = 0
			}
			curIdx = startIdx
		} else {
			startIdx = curIdx
		}

		var entCount int64 = 1000

		for index := startIdx; index < sth.TreeSize; index += entCount {
			stopIdx := index + entCount - 1
			if stopIdx >= sth.TreeSize {
				stopIdx = sth.TreeSize - 1
			}
			entries, err := downloadEntries(logURL, index, stopIdx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to download entries for %s: index %d -> %s\n", logURL, index, err)
				return
			}
			for _, ent := range entries.Entries {
				cInp <- &ent
			}
		}

		// Move our index to the end of the last tree
		curIdx = sth.TreeSize
		iteration++

		// Break after one loop unless we are in follow mode
		if !*optFollow {
			break
		}

	}
}

func logWriter(o <-chan *CTResult) {
	encOut := json.NewEncoder(os.Stdout)
	for record := range o {
		if err := encOut.Encode(record); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to marshal JSON: %v", err)
			continue
		}
		statOutput.Add(1)
		_ = os.Stdout.Sync()
	}
	wo.Done()
}

func logReader(c <-chan *CTEntry, o chan<- *CTResult) {

	for entry := range c {

		var leaf ct.MerkleTreeLeaf

		if rest, err := ct_tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to unmarshal MerkleTreeLeaf: %v (%v)", err, entry)
			continue
		} else if len(rest) > 0 {
			fmt.Fprintf(os.Stderr, "[-] Trailing data (%d bytes) after MerkleTreeLeaf: %q", len(rest), rest)
			continue
		}

		var cert *x509.Certificate
		var err error

		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:

			cert, err = x509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				fmt.Fprintf(os.Stderr, "[-] Failed to parse cert: %s\n", err.Error())
				continue
			}

		case ct.PrecertLogEntryType:

			cert, err = x509.ParseTBSCertificate(leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				fmt.Fprintf(os.Stderr, "[-] Failed to parse precert: %s\n", err.Error())
				continue
			}

		default:
			fmt.Fprintf(os.Stderr, "[-] Unknown entry type: %v (%v)", leaf.TimestampedEntry.EntryType, entry)
			continue
		}

		// Valid input
		statInput.Add(1)

		var names = make(map[string]struct{})

		if _, err := publicsuffix.EffectiveTLDPlusOne(cert.Subject.CommonName); err == nil {
			// Make sure this looks like an actual hostname or IP address
			if !(MatchIPv4.Match([]byte(cert.Subject.CommonName)) ||
				MatchIPv6.Match([]byte(cert.Subject.CommonName))) &&
				(strings.Contains(cert.Subject.CommonName, " ") ||
					strings.Contains(cert.Subject.CommonName, ":")) {
				continue
			}
			names[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
		}

		for _, alt := range cert.DNSNames {
			if _, err := publicsuffix.EffectiveTLDPlusOne(alt); err == nil {
				// Make sure this looks like an actual hostname or IP address
				if !(MatchIPv4.Match([]byte(cert.Subject.CommonName)) ||
					MatchIPv6.Match([]byte(cert.Subject.CommonName))) &&
					(strings.Contains(alt, " ") ||
						strings.Contains(alt, ":")) {
					continue
				}
				names[strings.ToLower(alt)] = struct{}{}
			}
		}

		sha1hash := ""

		// Write the names to the output channel
		for n := range names {
			if optPatternCompiled != nil && !optPatternCompiled.MatchString(n) {
				continue
			}

			if len(sha1hash) == 0 {
				sha1 := sha1.Sum(cert.Raw)
				sha1hash = hex.EncodeToString(sha1[:])
			}

			r := &CTResult{
				Name: n,
				TS:   leaf.TimestampedEntry.Timestamp,
				CN:   strings.ToLower(scrubX509Value(cert.Subject.CommonName)),
				SHA1: sha1hash,
			}

			// Dump associated email addresses if available
			for _, extra := range cert.EmailAddresses {
				r.Emails = append(r.Emails, strings.ToLower(scrubX509Value(extra)))
			}

			// Dump associated IP addresses if we have at least one name
			for _, extra := range cert.IPAddresses {
				r.IPs = append(r.IPs, extra.String())
			}

			// Dump associated SANs
			for _, extra := range cert.DNSNames {
				r.DNS = append(r.DNS, strings.ToLower(extra))
			}

			o <- r

		}
	}

	wi.Done()
}

func main() {
	flag.Usage = func() { usage() }
	optLogURL = flag.String("l", "", "Only read from the specified CT log url")
	optTailCount = flag.Int("n", 100, "The number of entries from the end to start from")
	optPollTime = flag.Int("p", 10, "The number of seconds to wait between polls")
	optFollow = flag.Bool("f", false, "Follow the tail of the CT log")
	optPattern = flag.String("m", "", "Only show entries matching this pattern")

	flag.Parse()

	if *optPattern != "" {
		var err error
		optPatternCompiled, err = regexp.Compile(*optPattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid pattern: %s\n", err.Error())
			return
		}
	}

	logs := []string{}
	if len(*optLogURL) > 0 {
		logs = append(logs, *optLogURL)
	} else {
		fmt.Fprintf(os.Stderr, "[+] Loading all known logs from %s\n", ChromeLogListURL)

		data, resp, err := downloadJSON(ChromeLogListURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to load log list: %s\n", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "[-] Failed to load log list: unexpected status code %d (%s)\n", resp.StatusCode, resp.Status)
			return
		}

		var logList ChromeLogs
		if err := json.Unmarshal(data, &logList); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to parse log list: %s\n", err.Error())
			return
		}

		for _, op := range logList.Operators {
			for _, src := range op.Logs {
				logs = append(logs, src.URL)
			}
		}

		fmt.Fprintf(os.Stderr, "[-] Loaded %d log servers\n", len(logs))
	}

	cInp := make(chan *CTEntry)
	cOut := make(chan *CTResult)
	for i := 0; i < runtime.NumCPU(); i++ {
		go logReader(cInp, cOut)
	}
	wi.Add(runtime.NumCPU())

	go logWriter(cOut)
	wo.Add(1)

	for _, logURL := range logs {
		go downloadLog(logURL, cInp)
		wd.Add(1)
	}

	wd.Wait()
	close(cInp)
	wi.Wait()
	close(cOut)
	wo.Wait()
}
