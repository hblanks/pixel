package pixel

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/http"
	"time"
)

type Server struct {
	listenAddress  string
	httpServer     *http.Server
	syslogAddress  string
	syslogPriority syslog.Priority
	logger         *log.Logger
	now            func() time.Time
}

// Every pixel GET or JSON POST is an event.
type Event struct {
	Time string `json:"t"`

	// Params are client-supplied event attributes.
	// Pixel events have params of form map[string]string.
	// JSON POST events have arbitrary JSON.
	Params interface{} `json:"params,omitempty"`

	UserAgent string `json:"ua,omitempty"`
	IP        string `json:"ip,omitempty"`
	Proto     string `json:"proto,omitempty"`

	// Error is a server-defined string reporting any error that
	// occurred while constructing the event, such as parse failures.
	Error string `json:"error,omitempty"`
}

const ISO8601Format = "2006-01-02T15:04:05Z"

var Transparent1PxGIF = []byte("\x47\x49\x46\x38\x39\x61\x01\x00" +
	"\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00" +
	"\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")

const UDPMaxBytes = 65507

var BadRequest = http.StatusText(http.StatusBadRequest)

const PostBodyMaxLen = 2048

var levelMap = map[string]syslog.Priority{
	"LOG_EMERG":   syslog.LOG_EMERG,
	"LOG_ALERT":   syslog.LOG_ALERT,
	"LOG_CRIT":    syslog.LOG_CRIT,
	"LOG_ERR":     syslog.LOG_ERR,
	"LOG_WARNING": syslog.LOG_WARNING,
	"LOG_NOTICE":  syslog.LOG_NOTICE,
	"LOG_INFO":    syslog.LOG_INFO,
	"LOG_DEBUG":   syslog.LOG_DEBUG,
}

var facilityMap = map[string]syslog.Priority{
	"LOG_KERN":     syslog.LOG_KERN,
	"LOG_USER":     syslog.LOG_USER,
	"LOG_MAIL":     syslog.LOG_MAIL,
	"LOG_DAEMON":   syslog.LOG_DAEMON,
	"LOG_AUTH":     syslog.LOG_AUTH,
	"LOG_SYSLOG":   syslog.LOG_SYSLOG,
	"LOG_LPR":      syslog.LOG_LPR,
	"LOG_NEWS":     syslog.LOG_NEWS,
	"LOG_UUCP":     syslog.LOG_UUCP,
	"LOG_CRON":     syslog.LOG_CRON,
	"LOG_AUTHPRIV": syslog.LOG_AUTHPRIV,
	"LOG_FTP":      syslog.LOG_FTP,
	"LOG_LOCAL0":   syslog.LOG_LOCAL0,
	"LOG_LOCAL1":   syslog.LOG_LOCAL1,
	"LOG_LOCAL2":   syslog.LOG_LOCAL2,
	"LOG_LOCAL3":   syslog.LOG_LOCAL3,
	"LOG_LOCAL4":   syslog.LOG_LOCAL4,
	"LOG_LOCAL5":   syslog.LOG_LOCAL5,
	"LOG_LOCAL6":   syslog.LOG_LOCAL6,
}

func NewSyslogPriority(level string, facility string) syslog.Priority {
	p, ok := levelMap[level]
	if !ok {
		p = syslog.LOG_INFO
	}

	f, ok := facilityMap[facility]
	if !ok {
		f = syslog.LOG_LOCAL7
	}

	return p | f
}

func NewServer(syslogAddress string, syslogPriority syslog.Priority) (*Server, error) {
	s := new(Server)
	s.syslogAddress = syslogAddress
	s.syslogPriority = syslogPriority

	writer, err := syslog.Dial("udp", s.syslogAddress, s.syslogPriority, "pixel")
	if err != nil {
		return nil, err
	}

	s.logger = log.New(writer, "", 0)
	s.now = time.Now
	return s, err
}

// Returns true if an interface is a flat mapping of strings to strings
// or numbers.
func isFlatJSON(i interface{}) bool {
	m, ok := i.(map[string]interface{})
	if !ok {
		return false
	}
	for _, v := range m {
		switch v.(type) {
		case string:
		case int:
		case float64:
			continue
		default:
			return false
		}
	}
	return true
}

// Returns a new *Event. *http.Request can be either a pixel or a
// JSON POST request.
func NewEvent(t time.Time, r *http.Request) (*Event, error) {
	event := &Event{
		Time:      t.UTC().Format(ISO8601Format),
		UserAgent: r.Header.Get("User-Agent"),
		IP:        r.Header.Get("X-Forwarded-For"),
		Proto:     r.Header.Get("X-Forwarded-Proto"),
	}
	var err error

	switch r.Method {
	case "GET":
		err = r.ParseForm()
		if err != nil {
			err = fmt.Errorf("Malformed query string: %s", err)
			break
		}

		params := make(map[string]string)
		for key, values := range r.Form {
			params[key] = values[0]
		}
		event.Params = params

	case "POST":
		if r.ContentLength == 0 {
			err = fmt.Errorf("Empty POST body")
			break
		}
		if r.ContentLength > PostBodyMaxLen {
			err = fmt.Errorf("POST body exceeds max length: %d", r.ContentLength)
			break
		}

		body := make([]byte, PostBodyMaxLen)

		var n int
		n, err = r.Body.Read(body)
		if err != nil && err != io.EOF {
			break
		}

		var params interface{}
		err = json.Unmarshal(body[:n], &params)
		if err != nil {
			break
		}
		event.Params = &params

	default:
		err = fmt.Errorf("Invalid method %s", r.Method)
	}

	if err != nil {
		event.Error = err.Error()
	}
	return event, err
}

func (s *Server) parseRequest(w http.ResponseWriter, r *http.Request) (*Event, error) {
	event, err := NewEvent(s.now(), r)
	if err != nil {
		log.Printf("%s", err)
		http.Error(w, BadRequest, http.StatusBadRequest)
	}
	return event, err
}

func (s *Server) logEvent(event *Event) {
	jsondata, err := json.Marshal(event)
	if err != nil {
		log.Printf("json encode error: %s", err)
	} else {
		s.logger.Printf("%s", jsondata)
	}
}

func (s *Server) trackPixel(w http.ResponseWriter, r *http.Request) {
	event, err := s.parseRequest(w, r)
	s.logEvent(event)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Write(Transparent1PxGIF)
}

func (s *Server) trackJSON(w http.ResponseWriter, r *http.Request) {
	event, err := s.parseRequest(w, r)
	s.logEvent(event)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.trackPixel(w, r)
		return

	case "POST":
		s.trackJSON(w, r)

	default:
		http.Error(w, BadRequest, http.StatusBadRequest)
	}
}

func (s *Server) ListenAndServe(address string) {
	s.httpServer = &http.Server{
		Addr:           address,
		Handler:        s,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.httpServer.ListenAndServe())
}
