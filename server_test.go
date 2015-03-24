package pixel

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"testing"
	"time"
)

var STATIC_TIME time.Time
var SYSLOG_REGEX *regexp.Regexp

const STATIC_ISO8601 = "2015-03-22T04:31:44Z"

func init() {
	SYSLOG_REGEX = regexp.MustCompile(`^<\d{3}>[^ ]+ [^ ]+ [^ ]+: (.*)\n$`)
	STATIC_TIME = time.Date(2015, 3, 22, 4, 31, 44, 0, time.UTC)
}

func assertEqual(t *testing.T, expected, actual interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		var expectedJSON, actualJSON []byte

		expectedJSON, _ = json.MarshalIndent(expected, "", "    ")
		actualJSON, _ = json.MarshalIndent(actual, "", "    ")

		t.Errorf("Expected != actual\n\n%s\n\n%s", expectedJSON,
			actualJSON)
	}
}

func emptyEvent(t *testing.T) (timestamp time.Time, r *http.Request, e *Event) {
	var err error
	r, err = http.NewRequest("GET", "http://localhost/393", nil)
	if err != nil {
		t.Fatal(err)
	}

	e = &Event{
		Time:   STATIC_ISO8601,
		Params: map[string]string{},
	}
	return STATIC_TIME, r, e
}

func newTestServer(t *testing.T, syslogAddress string) *Server {
	priority := NewSyslogPriority("", "")
	if syslogAddress == "" {
		syslogAddress = "localhost:5140"
	}
	server, err := NewServer(syslogAddress, priority) // XXX this should be a port we bound to.
	if err != nil {
		t.Fatal(err)
	}
	return server
}

//
// TestNewEvent*
//

var eventTests = []struct {
	headers map[string]string
	params  map[string]string
	IP      string
	proto   string
}{
	{
		map[string]string{},
		map[string]string{},
		"", "",
	},
	{
		map[string]string{
			"X-Forwarded-For":   "169.254.169.254",
			"X-Forwarded-Proto": "https",
		},
		map[string]string{},
		"169.254.169.254",
		"https",
	},
	{
		map[string]string{
			"X-Forwarded-For":   "169.254.169.254",
			"X-Forwarded-Proto": "https",
		},
		map[string]string{"k": "some_k", "foo": "gar"},
		"169.254.169.254",
		"https",
	},
}

func TestNewEvent(t *testing.T) {
	var k, v string
	var err error
	for _, eventTest := range eventTests {
		timestamp, r, expected := emptyEvent(t)
		for k, v = range eventTest.headers {
			r.Header.Set(k, v)
		}
		expected.IP = eventTest.IP
		expected.Proto = eventTest.proto

		params := url.Values{}
		for k, v = range eventTest.params {
			params.Set(k, v)
			expected.Params[k] = v
		}
		r.URL, err = url.Parse("http://localhost/")
		if err != nil {
			t.Fatal(err)
		}
		r.URL.RawQuery = params.Encode()

		actual, err := NewEvent(timestamp, r)
		if err != nil {
			t.Fatal(err)
		}

		assertEqual(t, expected, actual)
	}
}

//
// TestServeHTTP
//

var badRequest = http.StatusText(http.StatusBadRequest) + "\n"

var httpTests = []struct {
	method   string
	path     string
	rawQuery string
	code     int
	body     string
}{
	{"GET", "/", "", 200, TRANSPARENT_1_PX_GIF},
	{"GET", "/", "a=1&b=2", 200, TRANSPARENT_1_PX_GIF},
	{"GET", "/", "%gh&%ij", 400, badRequest},
	{"POST", "/", "", 400, badRequest},
}

func serveRequest(t *testing.T, server *Server, method, path,
	rawQuery string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	_, r, _ := emptyEvent(t)
	r.Method = method
	r.URL.Path = path
	r.URL.RawQuery = rawQuery

	server.ServeHTTP(w, r)
	return w
}

func TestServeHTTP(t *testing.T) {
	server := newTestServer(t, "")
	for _, httpTest := range httpTests {
		w := serveRequest(t, server, httpTest.method, httpTest.path,
			httpTest.rawQuery)

		expected := httpTest.body
		actual := w.Body.String()
		if expected != actual {
			t.Errorf("Expected body %q != actual %q", expected, actual)
		}
		if httpTest.code != w.Code {
			t.Errorf("Expected %d status code, but got %d.",
				httpTest.code, w.Code)
		}
	}
}

//
// TestSendUdp
//

const UDP_MAX_BYTES = 65507

func extractMessage(packet string) string {
	match := SYSLOG_REGEX.FindStringSubmatch(packet)
	if match == nil {
		return ""
	}
	return match[1]
}

var udpTests = []struct {
	method   string
	path     string
	rawQuery string
	packet   string
}{
	{
		"GET", "/", "a=1&b=2",
		`{"t":"` + STATIC_ISO8601 + `","params":{"a":"1","b":"2"}}`,
	},
	{
		"GET", "/", "%gh&%ij", "",
	},
	{
		"POST", "/", "a=1&b=2", "",
	},
}

func TestSendUdp(t *testing.T) {
	var err error
	var udpaddr *net.UDPAddr
	var udpconn *net.UDPConn

	udpaddr, err = net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	udpconn, err = net.ListenUDP("udp", udpaddr)
	defer udpconn.Close()
	if err != nil {
		t.Fatal(err)
	}

	server := newTestServer(t, udpconn.LocalAddr().String())
	server.now = func() time.Time { return STATIC_TIME }

	var numBytes int
	messageBuf := make([]byte, UDP_MAX_BYTES)

	for _, udpTest := range udpTests {
		serveRequest(t, server, udpTest.method, udpTest.path,
			udpTest.rawQuery)
		udpconn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

		numBytes, _, err = udpconn.ReadFromUDP(messageBuf)
		if err != nil {
			if udpTest.packet != "" {
				t.Errorf("Failed to read packet: %v", err)
			}
		} else {
			packet := string(messageBuf[:numBytes])
			if udpTest.packet == "" {
				t.Errorf("Expected no packet; received:\n\n    %s", packet)
				continue
			}

			actual := extractMessage(packet)
			if actual == "" {
				t.Errorf("Failed to parse packet:\n\n    %s", packet)
			}
			if udpTest.packet != actual {
				t.Errorf("Expected:\n\n    %s\n\nReceived:\n\n     %s",
					udpTest.packet, actual)
			}
		}
	}
}
