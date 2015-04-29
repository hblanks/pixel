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
	Params interface{} `json:"params"`

	UserAgent string `json:"ua,omitempty"`
	IP        string `json:"ip,omitempty"`
	Proto     string `json:"proto,omitempty"`
}

const ISO8601_FORMAT = "2006-01-02T15:04:05Z"

const TRANSPARENT_1_PX_GIF = "\x47\x49\x46\x38\x39\x61\x01\x00" +
	"\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00" +
	"\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"

var BAD_REQUEST string
var TRANSPARENT_1_PX_GIF_BYTES []byte

const POST_BODY_MAX_LEN = 2048

func init() {
	TRANSPARENT_1_PX_GIF_BYTES = []byte(TRANSPARENT_1_PX_GIF)
	BAD_REQUEST = http.StatusText(http.StatusBadRequest)
}

func NewSyslogPriority(level string, facility string) (p syslog.Priority) {
	switch level {
	case "LOG_EMERG":
		p = syslog.LOG_EMERG
	case "LOG_ALERT":
		p = syslog.LOG_ALERT
	case "LOG_CRIT":
		p = syslog.LOG_CRIT
	case "LOG_ERR":
		p = syslog.LOG_ERR
	case "LOG_WARNING":
		p = syslog.LOG_WARNING
	case "LOG_NOTICE":
		p = syslog.LOG_NOTICE
	case "LOG_INFO":
		p = syslog.LOG_INFO
	case "LOG_DEBUG":
		p = syslog.LOG_DEBUG
	default:
		p = syslog.LOG_INFO
	}

	switch facility {
	case "LOG_KERN":
		p |= syslog.LOG_KERN
	case "LOG_USER":
		p |= syslog.LOG_USER
	case "LOG_MAIL":
		p |= syslog.LOG_MAIL
	case "LOG_DAEMON":
		p |= syslog.LOG_DAEMON
	case "LOG_AUTH":
		p |= syslog.LOG_AUTH
	case "LOG_SYSLOG":
		p |= syslog.LOG_SYSLOG
	case "LOG_LPR":
		p |= syslog.LOG_LPR
	case "LOG_NEWS":
		p |= syslog.LOG_NEWS
	case "LOG_UUCP":
		p |= syslog.LOG_UUCP
	case "LOG_CRON":
		p |= syslog.LOG_CRON
	case "LOG_AUTHPRIV":
		p |= syslog.LOG_AUTHPRIV
	case "LOG_FTP":
		p |= syslog.LOG_FTP
	case "LOG_LOCAL0":
		p |= syslog.LOG_LOCAL0
	case "LOG_LOCAL1":
		p |= syslog.LOG_LOCAL1
	case "LOG_LOCAL2":
		p |= syslog.LOG_LOCAL2
	case "LOG_LOCAL3":
		p |= syslog.LOG_LOCAL3
	case "LOG_LOCAL4":
		p |= syslog.LOG_LOCAL4
	case "LOG_LOCAL5":
		p |= syslog.LOG_LOCAL5
	case "LOG_LOCAL6":
		p |= syslog.LOG_LOCAL6
	case "LOG_LOCAL7":
		p |= syslog.LOG_LOCAL7
	default:
		p |= syslog.LOG_LOCAL7
	}
	return p
}

func NewServer(syslogAddress string, syslogPriority syslog.Priority) (*Server, error) {
	var err error
	var writer *syslog.Writer
	s := new(Server)
	s.syslogAddress = syslogAddress
	s.syslogPriority = syslogPriority

	writer, err = syslog.Dial("udp", s.syslogAddress, s.syslogPriority,
		"pixel")

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
func NewEvent(t time.Time, r *http.Request) (event *Event, err error) {
	event = &Event{
		Time:      t.UTC().Format(ISO8601_FORMAT),
		UserAgent: r.Header.Get("User-Agent"),
		IP:        r.Header.Get("X-Forwarded-For"),
		Proto:     r.Header.Get("X-Forwarded-Proto"),
	}

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
		var body []byte
		var n int
		if r.ContentLength > 0 {
			if r.ContentLength > POST_BODY_MAX_LEN {
				err = fmt.Errorf("POST body exceeds max length: %d",
					r.ContentLength)
				break
			}
			body = make([]byte, r.ContentLength)
		} else if r.ContentLength == -1 {
			body = make([]byte, POST_BODY_MAX_LEN)
		} else {
			err = fmt.Errorf("Empty POST body")
			break
		}

		n, err = r.Body.Read(body)
		if err != nil && err != io.EOF {
			break
		}

		var params interface{}
		event.Params = &params
		err = json.Unmarshal(body[:n], event.Params)
		if err != nil {
			break
		}

	default:
		err = fmt.Errorf("Invalid method %s", r.Method)
	}
	return
}

func (s *Server) parseRequest(w http.ResponseWriter, r *http.Request) (event *Event, err error) {
	event, err = NewEvent(s.now(), r)
	if err != nil {
		log.Printf("%s", err)
		http.Error(w, BAD_REQUEST, http.StatusBadRequest)
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
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Write(TRANSPARENT_1_PX_GIF_BYTES)
	s.logEvent(event)
}

func (s *Server) trackJSON(w http.ResponseWriter, r *http.Request) {
	event, err := s.parseRequest(w, r)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
	s.logEvent(event)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.trackPixel(w, r)
		return

	case "POST":
		s.trackJSON(w, r)

	default:
		http.Error(w, BAD_REQUEST, http.StatusBadRequest)
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
