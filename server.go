package pixel

import (
	"encoding/json"
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

type Event struct {
	Time      string            `json:"t"`
	Params    map[string]string `json:"params"`
	UserAgent string            `json:"ua,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Proto     string            `json:"proto,omitempty"`
}

const ISO8601_FORMAT = "2006-01-02T15:04:05Z"

const TRANSPARENT_1_PX_GIF = "\x47\x49\x46\x38\x39\x61\x01\x00" +
	"\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00" +
	"\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"

var BAD_REQUEST string
var TRANSPARENT_1_PX_GIF_BYTES []byte

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
	// log.Printf("dial: %s %d", s.syslogAddress, s.syslogPriority)

	if err != nil {
		return nil, err
	}

	s.logger = log.New(writer, "", 0)
	s.now = time.Now
	return s, err
}

func NewEvent(t time.Time, r *http.Request) (event *Event, err error) {
	err = r.ParseForm()
	if err != nil {
		log.Printf("Malformed query string: %s", err)
		return
	}

	event = &Event{
		Time:   t.UTC().Format(ISO8601_FORMAT),
		Params: make(map[string]string),
	}

	for key, values := range r.Form {
		event.Params[key] = values[0]
	}

	event.UserAgent = r.Header.Get("User-Agent")
	event.IP = r.Header.Get("X-Forwarded-For")
	event.Proto = r.Header.Get("X-Forwarded-Proto")
	return event, err
}

func (s *Server) trackPixel(w http.ResponseWriter, r *http.Request) {
	var event *Event
	var err error
	var jsondata []byte

	event, err = NewEvent(s.now(), r)
	if err != nil {
		log.Printf("%s", err)
		http.Error(w, BAD_REQUEST, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "image/gif")
	w.Write(TRANSPARENT_1_PX_GIF_BYTES)

	jsondata, err = json.Marshal(event)
	if err != nil {
		log.Printf("json encode error: %s", err)
	} else {
		s.logger.Printf("%s", jsondata)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.trackPixel(w, r)
		return

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
