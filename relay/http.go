package relay

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/influxdata/influxdb/models"
)

// HTTP is a relay for HTTP influxdb writes
type HTTP struct {
	addr     string
	name     string
	schema   string
	database string

	gzip bool
	cert string
	rp   string

	closing int64
	l       net.Listener

	backends []*httpBackend
}

const (
	DefaultHTTPTimeout      = 10 * time.Second
	DefaultMaxDelayInterval = 10 * time.Second
	DefaultBatchSizeKB      = 512

	KB = 1024
	MB = 1024 * KB
)

func NewHTTP(cfg HTTPConfig) (Relay, error) {
	h := new(HTTP)

	h.addr = cfg.Addr
	h.name = cfg.Name

	h.gzip = cfg.Gzip
	h.cert = cfg.SSLCombinedPem
	h.rp = cfg.DefaultRetentionPolicy
	h.database = cfg.Database

	h.schema = "http"
	if h.cert != "" {
		h.schema = "https"
	}

	for i := range cfg.Outputs {
		backend, err := newHTTPBackend(&cfg.Outputs[i], cfg.Gzip)
		if err != nil {
			return nil, err
		}

		h.backends = append(h.backends, backend)
	}

	return h, nil
}

func (h *HTTP) Name() string {
	if h.name == "" {
		return fmt.Sprintf("%s://%s", h.schema, h.addr)
	}
	return h.name
}

func (h *HTTP) Run() error {
	l, err := net.Listen("tcp", h.addr)
	if err != nil {
		return err
	}

	// support HTTPS
	if h.cert != "" {
		cert, err := tls.LoadX509KeyPair(h.cert, h.cert)
		if err != nil {
			return err
		}

		l = tls.NewListener(l, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
	}

	h.l = l

	log.Printf("Starting %s relay %q on %v", strings.ToUpper(h.schema), h.Name(), h.addr)

	err = http.Serve(l, h)
	if atomic.LoadInt64(&h.closing) != 0 {
		return nil
	}
	return err
}

func (h *HTTP) Stop() error {
	atomic.StoreInt64(&h.closing, 1)
	return h.l.Close()
}

func (h *HTTP) WrapHandler(name string, hf http.HandlerFunc) http.Handler {
	var handler http.Handler
	handler = http.HandlerFunc(hf)
	return handler
}

func (h *HTTP) servePing(w http.ResponseWriter, r *http.Request) {
	//TODO ping should check all backend and return error if any of
	// them can not be pinged
	w.Header().Add("X-InfluxDB-Version", "relay")
	w.WriteHeader(http.StatusNoContent)

	return
}

func (h *HTTP) serveWrite(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	queryParams := r.URL.Query()

	// fail early if we're missing the database
	db := queryParams.Get("db")
	if db == "" {
		jsonError(w, http.StatusBadRequest, "missing parameter: db")
		return
	}

	if db != h.database {
		http.Error(w, "wrong database parameter", http.StatusBadRequest)
	}

	if queryParams.Get("rp") == "" && h.rp != "" {
		queryParams.Set("rp", h.rp)
	}

	var body = r.Body

	if r.Header.Get("Content-Encoding") == "gzip" {
		b, err := gzip.NewReader(r.Body)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "unable to decode gzip body")
		}
		defer b.Close()
		body = b
	}

	bodyBuf := getBuf()
	_, err := bodyBuf.ReadFrom(body)
	if err != nil {
		putBuf(bodyBuf)
		jsonError(w, http.StatusInternalServerError, "problem reading request body")
		return
	}

	precision := queryParams.Get("precision")
	points, err := models.ParsePointsWithPrecision(bodyBuf.Bytes(), start, precision)
	if err != nil {
		putBuf(bodyBuf)
		jsonError(w, http.StatusBadRequest, "unable to parse points")
		return
	}

	outBuf := getBuf()
	if h.gzip {
		writer := gzip.NewWriter(outBuf)

		for _, p := range points {
			if _, err := writer.Write([]byte(p.PrecisionString(precision))); err != nil {
				log.Println(err)
				return
			}

			if _, err := writer.Write([]byte("\n")); err != nil {
				log.Println(err)
				return
			}
		}

		if err := writer.Flush(); err != nil {
			log.Println(err)
			return
		}
		if err := writer.Close(); err != nil {
			log.Println(err)
			return
		}
	} else {
		for _, p := range points {
			if _, err = outBuf.WriteString(p.PrecisionString(precision)); err != nil {
				break
			}
			if err = outBuf.WriteByte('\n'); err != nil {
				break
			}
		}
	}

	// done with the input points
	putBuf(bodyBuf)

	if err != nil {
		putBuf(outBuf)
		jsonError(w, http.StatusInternalServerError, "problem writing points")
		return
	}

	// normalize query string
	query := queryParams.Encode()

	outBytes := outBuf.Bytes()

	// check for authorization performed via the header
	authHeader := r.Header.Get("Authorization")

	var wg sync.WaitGroup
	wg.Add(len(h.backends))

	var responses = make(chan *responseData, len(h.backends))

	for _, b := range h.backends {
		b := b
		go func() {
			defer wg.Done()
			resp, err := b.post(outBytes, query, authHeader, "write")
			if err != nil {
				log.Printf("Problem posting to relay %q backend %q: %v", h.Name(), b.name, err)
			} else {
				if resp.StatusCode/100 == 5 {
					log.Printf("5xx response for relay %q backend %q: %v", h.Name(), b.name, resp.StatusCode)
				}
				responses <- resp
			}
		}()
	}

	go func() {
		wg.Wait()
		close(responses)
		putBuf(outBuf)
	}()

	var errResponse *responseData

	for resp := range responses {
		switch resp.StatusCode / 100 {
		case 2:
			w.WriteHeader(http.StatusNoContent)
			return

		case 4:
			// user error
			resp.Write(w)
			return

		default:
			// hold on to one of the responses to return back to the client
			errResponse = resp
		}
	}

	// no successful writes
	if errResponse == nil {
		// failed to make any valid request...
		jsonError(w, http.StatusServiceUnavailable, "unable to write points")
		return
	}

	errResponse.Write(w)
}

func retryAllBackends(backends []*httpBackend, fn func(b *httpBackend) (*responseData, error)) (*responseData, error) {
	for _, b := range backends {
		resp, err := fn(b)
		if err == nil {
			return resp, nil
		}
	}

	return nil, errors.New("failed to query in all nodes")
}

func (h *HTTP) serveQuery(w http.ResponseWriter, r *http.Request) {
	queryParam := r.URL.Query()
	db := queryParam.Get("db")
	qp := queryParam.Get("q")
	if qp == "" {
		http.Error(w, "mising required parameter q", http.StatusBadRequest)
		return
	}

	if db == "" {
		http.Error(w, "mising required parameter db", http.StatusBadRequest)
		return
	}

	if db != h.database {
		http.Error(w, "database does not match", http.StatusBadRequest)
		return
	}

	// check for authorization performed via the header
	authHeader := r.Header.Get("Authorization")

	bodyB := []byte(fmt.Sprintf("db=%s&q=%s", db, qp))
	fn := func(b *httpBackend) (*responseData, error) {
		return b.post(bodyB, "", authHeader, "query")
	}

	resp, err := retryAllBackends(h.backends, fn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(resp.Body)
}

func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		switch r.URL.Path {
		case "/ping":
			h.WrapHandler("ping", h.servePing)
		case "/query":
			h.WrapHandler("query", h.serveQuery)
		}
	case "POST":
		switch r.URL.Path {
		case "/write":
			h.WrapHandler("write", h.serveWrite)
		}
	default:
		w.Header().Set("Allow", "POST")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			jsonError(w, http.StatusMethodNotAllowed, "invalid write method")
		}
		http.Error(w, "", http.StatusBadRequest)
	}

}

type responseData struct {
	ContentType     string
	ContentEncoding string
	StatusCode      int
	Body            []byte
}

func (rd *responseData) Write(w http.ResponseWriter) {
	if rd.ContentType != "" {
		w.Header().Set("Content-Type", rd.ContentType)
	}

	if rd.ContentEncoding != "" {
		w.Header().Set("Content-Encoding", rd.ContentEncoding)
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(rd.Body)))
	w.WriteHeader(rd.StatusCode)
	w.Write(rd.Body)
}

func jsonError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	data := fmt.Sprintf("{\"error\":%q}\n", message)
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.WriteHeader(code)
	w.Write([]byte(data))
}

type poster interface {
	post([]byte, string, string, string) (*responseData, error)
}

type simplePoster struct {
	client   *http.Client
	location string
	gzip     bool
}

func newSimplePoster(location string, timeout time.Duration, skipTLSVerification, gzip bool) *simplePoster {
	// Configure custom transport for http.Client
	// Used for support skip-tls-verification option
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerification,
		},
	}

	return &simplePoster{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		location: location,
		gzip:     gzip,
	}
}

func (b *simplePoster) post(buf []byte, query string, auth string, method string) (*responseData, error) {
	//in case of location is not absolute, concat a backslash
	if b.location[len(b.location)] != '/' {
		b.location += "/"
	}
	location := b.location + method
	req, err := http.NewRequest("POST", location, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	req.URL.RawQuery = query
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Length", strconv.Itoa(len(buf)))
	if b.gzip {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err = resp.Body.Close(); err != nil {
		return nil, err
	}

	return &responseData{
		ContentType:     resp.Header.Get("Conent-Type"),
		ContentEncoding: resp.Header.Get("Conent-Encoding"),
		StatusCode:      resp.StatusCode,
		Body:            data,
	}, nil
}

// a httpBackend contains mutiple poster, name and database name. Per request, determine the db first and
// write such request in all poster if db matches what it has
type httpBackend struct {
	poster
	name string
}

func newHTTPBackend(cfg *HTTPOutputConfig, gzip bool) (*httpBackend, error) {
	if cfg.Name == "" {
		cfg.Name = cfg.Location
	}

	timeout := DefaultHTTPTimeout
	if cfg.Timeout != "" {
		t, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("error parsing HTTP timeout '%v'", err)
		}
		timeout = t
	}

	var p poster = newSimplePoster(cfg.Location, timeout, cfg.SkipTLSVerification, gzip)

	// If configured, create a retryBuffer per backend.
	// This way we serialize retries against each backend.
	if cfg.BufferSizeMB > 0 {
		max := DefaultMaxDelayInterval
		if cfg.MaxDelayInterval != "" {
			m, err := time.ParseDuration(cfg.MaxDelayInterval)
			if err != nil {
				return nil, fmt.Errorf("error parsing max retry time %v", err)
			}
			max = m
		}

		batch := DefaultBatchSizeKB * KB
		if cfg.MaxBatchKB > 0 {
			batch = cfg.MaxBatchKB * KB
		}

		p = newRetryBuffer(cfg.BufferSizeMB*MB, batch, max, p)
	}

	return &httpBackend{
		poster: p,
		name:   cfg.Name,
	}, nil
}

var ErrBufferFull = errors.New("retry buffer full")

var bufPool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}

func getBuf() *bytes.Buffer {
	if bb, ok := bufPool.Get().(*bytes.Buffer); ok {
		return bb
	}
	return new(bytes.Buffer)
}

func putBuf(b *bytes.Buffer) {
	b.Reset()
	bufPool.Put(b)
}
