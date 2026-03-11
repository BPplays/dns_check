package dns_check

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"time"

	// "unicode"

	"github.com/mattn/go-runewidth"
)

type Config struct {
	Forwarders []ForwarderGroup
	LogWriter io.Writer
	DnsResolveTimeout time.Duration
	DnsResolveRetries int

	Debug bool
	NoNonErr bool
	NoPrintDnsErr bool
	AllPrintDnsErr bool
	NoTime bool
	CpuProfile bool
	TraceProf bool


}

type ForwarderType string
var debug *bool
var noNonErr *bool
var noTime *bool
var noPrintDnsErr *bool
var allPrintDnsErr *bool

const (
    ForwarderTypeDNS      ForwarderType = "dns"
    ForwarderTypeTLS      ForwarderType = "tls"
    ForwarderTypeHTTP     ForwarderType = "http"
    ForwarderTypeDNSCrypt ForwarderType = "dnscrypt"
)

type customWriter struct {
    w io.Writer
    layout string
}

func (cw *customWriter) Write(p []byte) (n int, err error) {
    ts := time.Now().Format(cw.layout)
    // write timestamp + space + original log bytes
    return cw.w.Write(append([]byte(ts+" "), p...))
}

var (
	errUnsupportedForwarderType error = errors.New("Unsupported ForwarderType")
	errContextWithDeadlineRequired error = errors.New("you must use a context with a deadline")
)

const (
	prog_name = "opnsense_dns_auto"
	Version = "1.0.9"

	// DefaultLogFormat string = "2006年01月02日 15:04:05.000"
	DefaultLogFormat string = "2006年01月02日 15時04分05.000秒"
)

type opnUnboundapiRow struct {
	UUID    string `json:"uuid"`
	Server  string `json:"server"`
	Port    string `json:"port"`
	Enabled string `json:"enabled"`
}

type toggleResponse struct {
	Changed bool `json:"changed"`
	Result string `json:"result"`
}

type opnUnboundApiResponse struct {
	Rows []opnUnboundapiRow `json:"rows"`
}


type ActiveForwarder struct {
	Forwarder Forwarder
	Resolved bool
	Priority int64  // lower is first
}

type Forwarder struct {
	Server   netip.AddrPort  `yaml:"server"`
	Test_domains   []string  `yaml:"test_domains"`
	Ftype ForwarderType      `yaml:"ftype"`  // 'dns', 'tls', 'http', 'dnscrypt'
	// opts dnsOpts             `yaml:"opts"`
}

type ForwarderGroup struct {
	Name string `yaml:"name"`
	Forwarders []Forwarder     `yaml:"forwarders"`
	Opts dnsOpts             `yaml:"opts"`
}

type dnsOpts struct {
	maxTtl time.Duration
	// minTtl time.Duration
	// messageCacheSize string
	// rrsetCacheSize string
	dnssec bool
}

type uuidSetResult struct {
	uuid string
	enabled *bool
	changed bool
	ftype ForwarderType
}

type uuidSet struct {
	uuid string
	currentlyEnabled bool
	shouldEnable bool
	ftype ForwarderType
}

type uuidUrl struct {
	apiURL string
	ftype ForwarderType
}

type indexStatus struct {
	index int
	enabled bool
}

func resultToBool(s string) (*bool, error) {
	t := true
	f := false
	switch {
	case strings.ToLower(s) == "enabled" || strings.ToLower(s) == "enable":
		return &t, nil

	case strings.ToLower(s) == "disabled" || strings.ToLower(s) == "disable":
		return &f, nil
	default:
		return nil, errors.New("did not convert")
	}
}

func (opts dnsOpts) prettySprint() string {
	return fmt.Sprintf("maxttl: %vs, dnssec: %v", opts.maxTtl.Seconds(), opts.dnssec)
}

func DefaultDnsOpts() dnsOpts {
    return dnsOpts{
        maxTtl:   10000 * time.Second,
		dnssec: true,
        // minTtl:   0 * time.Second,
		// messageCacheSize: "50m",
		// rrsetCacheSize: "100m",
    }
}

func getLogLen(flags int) int {
	logDefaultTimestamp := getLogNothingText(flags)

	// logDefaultTimestamp = strings.TrimRightFunc(logDefaultTimestamp, unicode.I)


	logDefaultSize := runewidth.StringWidth(logDefaultTimestamp)

	return logDefaultSize

}

func makeResolveCtx(ctx context.Context, lookupTimeout time.Duration) (context.Context, context.CancelFunc){
	ctxd, ok := ctx.Deadline()
	if !ok {
		ctxd = time.Now()
	}

	lctx, lcan := context.WithTimeout(ctx, lookupTimeout)

	dl, ok := lctx.Deadline()
	if ok {
		if dl.After(ctxd) {
			lctx, lcan = context.WithDeadline(ctx, ctxd)
		}
	}

	return lctx, lcan
}

func sprintTime(td time.Duration) string {
	limit_prefix := ""
	switch {
	case td.Nanoseconds() < 1000:
		limit_prefix = "nano"
		// return fmt.Sprintf("%vns", td.Nanoseconds())

	case td.Microseconds() < 1000:
		limit_prefix = "nano"
		// return fmt.Sprintf("%vμs", td.Microseconds())

	case td.Milliseconds() < 1000:
		limit_prefix = "micro"
		// return fmt.Sprintf("%vms", td.Milliseconds())

	case td.Seconds() < 1000:
		limit_prefix = "milli"
		// return fmt.Sprintf("%vs", td.Seconds())

	case (td.Seconds() / 1000) < 10000:
		limit_prefix = "none"
		// return fmt.Sprintf("%vks", (td.Seconds() / 1000))

	default:
		return td.String()
	}

	var utime *big.Int
	utime = big.NewInt(0)

	// epochTime := td.Seconds()
	ns := td.Nanoseconds()
	// fmt.Println(ns)
	// utime = big.NewInt(epochTime)
	tmp := big.NewInt(0)
	tmp2 := big.NewInt(0)
	qsbi := big.NewInt(qsec_pow*-1)
	// 10bi := big.NewInt(10)
	tbi := big.NewInt(10)
	tmp.Exp(tbi, qsbi, nil)
	// fmt.Println(tmp)
	utime.Mul(utime, tmp)



	tmp.Mul(big.NewInt(int64(ns)), tmp2.Exp(big.NewInt(10), big.NewInt((qsec_pow*-1) + (MetricAllPrefixes["nano"].Pow)), nil))

	utime.Add(utime, tmp)

	return fmt_epoch_to_prefixsec(utime, &MetricCommonPrefixes, limit_prefix)
}

func sprintForwarderGroup(fg ForwarderGroup, shift int, logLen int) (string) {
	var sb strings.Builder
	var ssl []string
	for _, f := range fg.Forwarders {
		ssl = append(ssl, f.Server.String())
	}
	sftStr := strings.Repeat(" ", shift)
	loglStr := strings.Repeat(" ", logLen)

	sb.WriteString(fmt.Sprintf("%vusing forwarder group:\n", sftStr))
	sb.WriteString(fmt.Sprintf("    %v%v%v: %v\n", sftStr, loglStr, fg.Name, strings.Join(ssl, ", ")))
	sb.WriteString(fmt.Sprintf("    %v%vusing opts (not impl yet, also quad9 ::11 does dnssec itself): %v", sftStr, loglStr, fg.Opts.prettySprint()))
	return sb.String()
}

func getLogNothingText(logFlags int) (string) {
    var buf bytes.Buffer

    logger := log.New(&customWriter{
		w: &buf,
		layout: DefaultLogFormat,
	}, "", logFlags)

    logger.Print("")

    raw := buf.String()

	return raw
}

func shouldEnableNums(uuids []uuidSet) (numEnabled uint64) {
	numEnabled = 0

	for _, uuid := range uuids {
		if uuid.shouldEnable == true {
			numEnabled++
		}
	}
	return numEnabled
}

func getIntChanLowest(iChan <-chan int) (int, error) {
	var lowest int = math.MaxInt
	var found bool

	for int := range iChan {

		if !*noNonErr {
			fmt.Printf("current chan lowest int is %v\n", int)
		}

		if (!found) || (int < lowest) {
			if !*noNonErr {
				fmt.Printf(
					"current chan lowest int %v is lower then last (%v)\n",
					int,
					lowest,
				)
			}

			lowest = int
			found = true
		}
	}

	if !found { return math.MaxInt, errors.New("no lowest chan") }

	return lowest, nil
}

// func parseUint16(strVal string) (uint16, error) {
// 	uint64Val, err := strconv.ParseUint(strVal, 10, 16)
// 	if err != nil {
// 		return 0, err
// 	}
//
// 	return uint16(uint64Val), nil
// }

func filter[T any](input []T, test func(T) bool) []T {
	var result []T
	for _, v := range input {
		if test(v) {
			result = append(result, v)
		}
	}
	return result
}

func notInSlice(s string, list []uuidSet) bool {
	for _, v := range list {
		if v.uuid == s {
			return false
		}
	}
	return true
}

// func setMaxTtl(apiURL, apiKey, apiSecret, uuid string, enable bool, retry int) (bool, error) {
// 	var err error
//
// 	togNum := 0
// 	if enable {
// 		togNum = 1
// 	}
//
// 	url := fmt.Sprintf("%s/api/unbound/settings/toggleForward/%s/%d", apiURL, uuid, togNum)
//
// 	for range retry {
//
//
// 		// HTTP client skipping TLS verify
// 		tr := &http.Transport{
// 			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
// 		}
// 		client := &http.Client{Transport: tr}
//
// 		// Build and send POST
// 		req, err := http.NewRequest("POST", url, nil)
// 		if err != nil {
// 			err = fmt.Errorf("creating request: %w", err)
// 			continue
// 		}
// 		req.SetBasicAuth(apiKey, apiSecret)
//
// 		resp, err := client.Do(req)
// 		if err != nil {
// 			err = fmt.Errorf("request error: %w", err)
// 			continue
// 		}
// 		defer resp.Body.Close()
//
// 		// Read and handle response
// 		body, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			err = fmt.Errorf("reading body: %w", err)
// 			continue
// 		}
//
// 		if resp.StatusCode != http.StatusOK {
// 			err = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
// 			continue
// 		}
//
// 		var trsp toggleResponse
// 		if err := json.Unmarshal(body, &trsp); err != nil {
// 			err = fmt.Errorf("invalid JSON: %w", err)
// 			continue
// 		}
//
// 		if !*noNonErr {
// 			log.Println("Forwarder toggled successfully!")
// 			log.Printf("%+v\n", trsp)
// 		}
//
// 		return trsp.Changed, nil
// 	}
// 	return false, err
// }

// setUUID toggles a forwarder on or off.
// Returns true if the server reports that something changed.
func setUUID(
	apiURL, apiKey, apiSecret string,
	uuid uuidSet,
	retry int,
) (changed bool, enabled *bool, err error) {
	if uuid.shouldEnable == uuid.currentlyEnabled { return false, nil, nil }

	// var err error
	var toggleUrl string

	var togNum int = 0
	if uuid.shouldEnable { togNum = 1 }

	switch {
	case uuid.ftype == ForwarderTypeTLS:
		toggleUrl = "toggleDot"
	case uuid.ftype == ForwarderTypeDNS:
		toggleUrl = "toggleForward"
	default:
		return false, nil, errUnsupportedForwarderType
	}

	url := fmt.Sprintf(
		"%s/api/unbound/settings/%s/%s/%d",
		apiURL,
		toggleUrl,
		uuid.uuid,
		togNum,
	)

	if *debug {
		log.Println("url setuuid:", url)
	}

	for range retry {


		// HTTP client skipping TLS verify
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// Build and send POST
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			err = fmt.Errorf("creating request: %w", err)
			continue
		}
		req.SetBasicAuth(apiKey, apiSecret)

		resp, err := client.Do(req)
		if err != nil {
			err = fmt.Errorf("request error: %w", err)
			continue
		}
		defer resp.Body.Close()

		// Read and handle response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("reading body: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
			continue
		}

		var trsp toggleResponse
		if err := json.Unmarshal(body, &trsp); err != nil {
			err = fmt.Errorf("invalid JSON: %w", err)
			continue
		}

		if !*noNonErr {
			log.Println("Forwarder toggled successfully!")
			log.Printf("%+v\n", trsp)
		}

		respEnabled, err := resultToBool(trsp.Result)
		if err != nil {
			log.Printf("can't decode result: %v", string(body))
		}

		return trsp.Changed, respEnabled, nil
	}
	return false, nil, err
}


func setUUIDS(
	uuids []uuidSet,
	apiURL, apiKey, apiSecret string,
) (chan uuidSetResult) {
	var wg sync.WaitGroup



	totalTasks := 1
	for range uuids {
		totalTasks += 1
	}
	results := make(chan uuidSetResult, totalTasks)

	for i, fwds := range uuids {
		wg.Add(1)

		go func(fwds uuidSet, i int) {
			defer wg.Done()

			// resolve_timeout := 90 * time.Millisecond
			// retries := 5
			//
			// total_time := resolve_timeout * time.Duration(retries)
			//
			// // fmt.Println(total_time)
			// ctx, cancel := context.WithTimeout(context.Background(), total_time)
			// defer cancel()


			changed, enabled, err := setUUID(apiURL, apiKey, apiSecret, fwds, 15)
			if err != nil {
				log.Println(err)
				return
			}

			results <- uuidSetResult{
				uuid: fwds.uuid,
				changed: changed,
				enabled: enabled,
				ftype: fwds.ftype,
			}
		}(fwds, i)
	}

	// log.Println("waiting uuids")

	wg.Wait()
	// log.Println("waited uuids")
	close(results)
	return results

}

// reconfig calls the reconfigure endpoint.
// Returns the full JSON response as a map for maximum flexibility.
func reconfig(
	apiURL, apiKey, apiSecret string,
	retry int,
) (map[string]any, error) {
	var err error
	url := fmt.Sprintf("%s/api/unbound/service/reconfigure", apiURL)


	for range retry {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			err = fmt.Errorf("creating request: %w", err)
			continue
		}
		req.SetBasicAuth(apiKey, apiSecret)

		resp, err := client.Do(req)
		if err != nil {
			err = fmt.Errorf("request error: %w", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("reading body: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			err = fmt.Errorf("invalid JSON: %w", err)
			continue
		}

		if !*noNonErr {
			fmt.Println("Reconfigure successful!")
			fmt.Printf("%+v\n", result)
		}
		return result, nil
	}

	return map[string]any{}, err
}

func isTargetHere(targets ForwarderGroup, row opnUnboundapiRow) (bool) {
	for _, tgt := range targets.Forwarders {
		portStr := strconv.FormatUint(uint64(tgt.Server.Port()), 10)

		if row.Server == tgt.Server.Addr().String() &&
		row.Port == portStr {
			return true
		}
	}

	return false

}

func findMatchingUUIDs(
	uuidURLs []uuidUrl,
	apiKey, apiSecret string,
	targets ForwarderGroup,
) (found_uuids []uuidSet, err error) {
	// build an HTTP client that skips TLS verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for _, uuidURL := range uuidURLs {
		apiURL := uuidURL.apiURL
		// create the request
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.SetBasicAuth(apiKey, apiSecret)

		// send the request
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request error: %w", err)
		}
		defer resp.Body.Close()

		// check status code
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status: %s", resp.Status)
		}

		// read and parse body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		// fmt.Println(string(body))

		var data opnUnboundApiResponse
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		// log.Println(data.Rows)


		// search through rows
		for _, row := range data.Rows {
			// found := false

			// port, err := parseUint16(row.Port)
			// if err != nil {
			// 	continue
			// }

			enabled, err := strconv.ParseBool(row.Enabled)
			if err != nil {
				log.Printf("can't parse bool: %v", row.Enabled)
				continue
			}

			uuidr := uuidSet{
				uuid: row.UUID,
				currentlyEnabled: enabled,
				shouldEnable: false,
				ftype: uuidURL.ftype,
			}

			uuidr.shouldEnable = isTargetHere(targets, row)

			found_uuids = append(found_uuids, uuidr)

			// // if it didn't match, but is enabled, add to disabled list
			// if !found && row.Enabled == "1" {
			// 	disabled = append(disabled, row.UUID)
			// }
		}
	}

	return found_uuids, nil
}

func makeResolver(
	ftype ForwarderType,
	timeout time.Duration,
	dnsServer netip.AddrPort,
) (resolver *net.Resolver, err error) {
	switch {
	case ftype == ForwarderTypeTLS:
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// 1) Dial a plain TCP connection to port 853
				d := net.Dialer{Timeout: timeout}
				tcpConn, err := d.DialContext(ctx, "tcp", dnsServer.String())
				if err != nil {
					return nil, err
				}

				// 2) Wrap it in TLS
				tlsConn := tls.Client(tcpConn, &tls.Config{
					ServerName:         dnsServer.Addr().String(), // must match the server's cert
					InsecureSkipVerify: false,                     // set true only for testing!
				})
				if err := tlsConn.Handshake(); err != nil {
					tcpConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}

	case ftype == ForwarderTypeDNS:

		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: timeout,
				}
				return d.DialContext(ctx, "udp", dnsServer.String())
			},
		}
	default:
		err = errUnsupportedForwarderType
		return nil, err

	}

	return resolver, nil

}

func resolveWithRetries(
	dnsServer netip.AddrPort,
	hostname string,
	retries int,
	timeout time.Duration,
	ftype ForwarderType,
	ctx context.Context,
) (resolved bool, requests int64, retErrs []error) {


    resolver, err := makeResolver(ftype, timeout, dnsServer)
    if err != nil {
		return false, 0, []error{err}
    }

	var ltimeout time.Duration
	ctxd, ok := ctx.Deadline()
	if ok {
		ltimeout = ctxd.Sub(time.Now())
		ltimeout = ltimeout / time.Duration(retries)
	} else {
		retErrs = append(retErrs, errContextWithDeadlineRequired)
		return false, requests, retErrs
	}

	for i := range retries {
		if ctx.Err() != nil {
			return false, requests, nil
		}

		lctx, lcan := makeResolveCtx(ctx, ltimeout)
		defer lcan()


		_, err := resolver.LookupIP(lctx, "ip", hostname)
		requests++
		if err == nil {
			return true, requests, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			switch {
			case dnsErr.IsTimeout:
				if *allPrintDnsErr {
					log.Printf("dns timeout: %v", dnsErr)
				}

			case dnsErr.IsNotFound:
				if *allPrintDnsErr {
					log.Printf("dns not found: %v", dnsErr)
				}
			case dnsErr.IsTemporary:
				if *allPrintDnsErr {
					log.Printf("dns temp: %v", dnsErr)
				}

			default:
				if !*noPrintDnsErr {
					log.Printf("dns misc: %v", dnsErr)
				}
			}
		} else {
			retErrs = append(retErrs, err)
		}
		if *allPrintDnsErr {
			log.Println("loops of rwr", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false, requests, retErrs
}


func checkServers(
	ctx context.Context,
	fowarders []Forwarder,
	retries int,
	timeout time.Duration,
) (bool, int64) {
	totalTasks := 0
	for _, srv := range fowarders {
		totalTasks += len(srv.Test_domains)
	}
	// fmt.Println(totalTasks)

	results := make(chan bool, totalTasks)
	numRequests := make(chan int64, totalTasks)
	var wg sync.WaitGroup

	for _, srv := range fowarders {
		if srv.Test_domains == nil {
			continue
		}
		for _, test_domain := range srv.Test_domains {
			wg.Add(1)
			go func(
				srv Forwarder,
				test_domain string,
				ctx context.Context,
				retries int,
				timeout time.Duration,
			) {
				defer wg.Done()
				// fmt.Println(srv)

				var (
					r bool = false
					requests int64 = 0
					// retErr error = errors.New("no dns type selected")
					errs []error
				)

				r, requests, errs = resolveWithRetries(
					srv.Server,
					test_domain,
					retries,
					timeout,
					srv.Ftype,
					ctx,
				)
				for _, err := range errs {
					if (err != nil) && (*debug) {
						log.Printf("%v: %v\n", srv.Server.String(), err)
					}
				}

				results <- r
				numRequests <- requests
				// fmt.Println("cs inner done")

			}(srv, test_domain, ctx, retries, timeout)
		}
	}
	// fmt.Println("cs waiting")

	wg.Wait()
	close(results)
	close(numRequests)

	// fmt.Println("cs done")

	var totalRequests int64 = 0
	for req := range numRequests {
		totalRequests += req
	}

	for res := range results {
		if res {
			return true, totalRequests
		}
	}

	return false, totalRequests
}



func getFwds(
	ctx context.Context,
	conf Config,
	forwarders []ForwarderGroup,
) (chan int, int64) {
	var wg sync.WaitGroup



	totalTasks := 0
	for range forwarders {
		totalTasks += 1
	}
	// log.Println("total tasks", totalTasks)
	results := make(chan int, totalTasks)
	numRequests := make(chan int64, totalTasks)

	// log.Println("adding fwd")
	for i, fwds := range forwarders {
		wg.Add(1)

		go func(ctx context.Context, fwds []Forwarder, i int) {
			defer wg.Done()

			resolve_timeout := conf.DnsResolveTimeout
			retries := conf.DnsResolveRetries

			total_time := resolve_timeout * time.Duration(retries)

			ctx, cancel := context.WithTimeout(ctx, total_time)
			defer cancel()


			r, requests := checkServers(
				ctx,
				fwds,
				retries,
				resolve_timeout,
			)
			if r {
				results <- i
			}
			numRequests <- requests
		}(ctx, fwds.Forwarders, i)
	}

	// log.Println("waiting fwd")

	wg.Wait()
	// log.Println("waited fwd")
	close(results)
	close(numRequests)

	var totalRequests int64 = 0
	for req := range numRequests {
		totalRequests += req
	}

	// log.Println("closed fwd")
	return results, totalRequests

}

func sleepUntilTime(until *time.Duration, startTime *time.Time, minimum *time.Duration) (time.Duration) {
	sleepTime := *until - time.Since(*startTime)

	if sleepTime > *minimum {
		return sleepTime
	} else {
		return (*minimum)
	}
}

// func sleepUntil(until *time.Duration, startTime *time.Time, minimum *time.Duration) {
// 	sleepTime := sleepUntilTime(until, startTime, minimum)
// 	time.Sleep(sleepTime)
// }



func Run(conf Config) (int, error) {
	return RunWithContext(context.Background(), conf)
}


func RunWithContext(ctx context.Context, conf Config) (int, error) {
	if conf.DnsResolveRetries <= 0 {
		conf.DnsResolveRetries = 5
	}

	if conf.DnsResolveTimeout <= 0 {
		conf.DnsResolveTimeout = 150 * time.Millisecond
	}

	// var logDefaultFlags = log.Ldate | log.Ltime
	var logDefaultFlags = 0


	cpuProfile := &conf.CpuProfile
	traceProf := &conf.TraceProf

	debug = &conf.Debug
	noNonErr = &conf.NoNonErr
	noPrintDnsErr = &conf.NoPrintDnsErr
	allPrintDnsErr = &conf.AllPrintDnsErr
	noTime = &conf.NoTime

	flag.Parse()


	if *traceProf {
		cwd, err := os.Getwd()
		if err != nil {
			log.Fatalln(err)
		}
		filePatht := filepath.Join(cwd, "trace.out")
		filet, err := os.Create(filePatht)
		if err != nil {
			return math.MinInt, err
		}

		trace.Start(filet)

	}

	if *cpuProfile {
		cwd, err := os.Getwd()
		if err != nil {
			// log.Fatalln(err)

			return math.MinInt, err
		}

		filePathp := filepath.Join(cwd, "cpuprof")
		filep, err := os.Create(filePathp)
		if err != nil {
			return math.MinInt, err
		}


		pprof.StartCPUProfile(filep)
        defer pprof.StopCPUProfile()

	}

	log.SetFlags(logDefaultFlags)

	log.SetOutput(conf.LogWriter)



	forwarders := conf.Forwarders


	select {
	case <-ctx.Done():
		return math.MinInt, ctx.Err()
	default:
	}
	fwdsResults, _ := getFwds(ctx, conf, forwarders)

	// fwdsTime := time.Since(startTime)

	if fwdsResults == nil {
		// log.Println("fwdsres nil")
		return math.MinInt, errors.New("fwdsResults nil")
	}
	select {
	case <-ctx.Done():
		return math.MinInt, ctx.Err()
	default:
	}

	lowestFwd, err := getIntChanLowest(fwdsResults)
	if err != nil {
		// log.Printf("%v\n", err)
		return math.MinInt, err
	}

	select {
	case <-ctx.Done():
		return math.MinInt, ctx.Err()
	default:
	}

	return lowestFwd, nil

}

