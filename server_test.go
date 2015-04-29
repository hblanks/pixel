package pixel

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
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

func assertEqual(t *testing.T, prefix string, expected, actual interface{}) {
	if !reflect.DeepEqual(actual, expected) {
		var expectedJSON, actualJSON []byte

		expectedJSON, _ = json.MarshalIndent(expected, "", "    ")
		actualJSON, _ = json.MarshalIndent(actual, "", "    ")

		t.Errorf("%s - expected != actual:\n\n%s\n!=\n%s",
			prefix, expectedJSON, actualJSON)
	}
}

func emptyEvent(t *testing.T, body string) (timestamp time.Time, r *http.Request, e *Event) {
	var err error
	if body == "" {
		r, err = http.NewRequest("GET", "http://localhost/393", nil)
	} else {
		r, err = http.NewRequest("POST", "http://localhost/393",
			ioutil.NopCloser(strings.NewReader(body)))
		r.ContentLength = int64(len(body))
	}
	if err != nil {
		t.Fatal(err)
	}

	e = &Event{
		Time:   STATIC_ISO8601,
		Params: make(map[string]string),
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
	IP      string
	proto   string
	params  map[string]string
	body    string
}{
	// GET requests
	{
		map[string]string{},
		"",
		"",
		map[string]string{},
		"",
	},
	{
		map[string]string{
			"X-Forwarded-For":   "169.254.169.254",
			"X-Forwarded-Proto": "https",
		},
		"169.254.169.254",
		"https",
		map[string]string{},
		"",
	},
	{
		map[string]string{
			"X-Forwarded-For":   "169.254.169.254",
			"X-Forwarded-Proto": "https",
		},
		"169.254.169.254",
		"https",
		map[string]string{"k": "some_k", "foo": "gar"},
		"",
	},
	// POST requests
	{
		map[string]string{},
		"",
		"",
		nil,
		`{"k": "some_k", "foo": "gar"}`,
	},
}

func TestNewEvent(t *testing.T) {
	var k, v string
	var err error
	var r *http.Request
	var timestamp time.Time
	var expected *Event

	check := func(prefix string) {
		actual, err := NewEvent(timestamp, r)
		if err != nil {
			t.Fatalf("%s - %s", prefix, err)
		}
		assertEqual(t, prefix, expected, actual)
	}

	for index, eventTest := range eventTests {
		timestamp, r, expected = emptyEvent(t, eventTest.body)
		for k, v = range eventTest.headers {
			r.Header.Set(k, v)
		}
		expected.IP = eventTest.IP
		expected.Proto = eventTest.proto

		if eventTest.body == "" {
			eventParams := make(map[string]string)
			urlParams := url.Values{}
			for k, v = range eventTest.params {
				urlParams.Set(k, v)
				eventParams[k] = v
			}
			expected.Params = eventParams

			r.URL, err = url.Parse("http://localhost/")
			if err != nil {
				t.Fatal(index, err)
			}
			r.URL.RawQuery = urlParams.Encode()
			check(string(index))
		} else {
			var p interface{}
			expected.Params = &p
			err = json.Unmarshal([]byte(eventTest.body),
				expected.Params)
			if err != nil {
				t.Fatal(index, err)
			}
			check(strconv.Itoa(index))

			// Re-test the request with no content-length set.
			r.Body = ioutil.NopCloser(strings.NewReader(eventTest.body))
			r.ContentLength = -1
			check(strconv.Itoa(index))
		}

	}
}

//
// TestServeHTTP
//

var badRequest = http.StatusText(http.StatusBadRequest) + "\n"

var httpTests = []struct {
	method       string
	path         string
	rawParams    string
	code         int
	responseBody string
}{
	// Valid requests
	{"GET", "/", "", 200, TRANSPARENT_1_PX_GIF},
	{"GET", "/", "a=1&b=2", 200, TRANSPARENT_1_PX_GIF},
	{"POST", "/", `{}`, 200, "{}"},
	{"POST", "/", `{"a": 1, "b": "2"}`, 200, "{}"},

	// Invalid requests
	{"GET", "/", "%gh&%ij", 400, badRequest},
	{"POST", "/", "", 400, badRequest},
	{"POST", "/", `{"a": 1 "b": "2"}`, 400, badRequest},
	{"POST", "/",
		`{"a": 1, "b": "paddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpadd"}`,
		400, badRequest},
	{"POST", "/", `{"a": 1, "b": {"a": 1}`, 400, badRequest},
}

func serveRequest(t *testing.T, server *Server, method, path,
	rawParams string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var r *http.Request
	switch method {
	case "GET":
		_, r, _ = emptyEvent(t, "")
		r.URL.RawQuery = rawParams
	case "POST":
		_, r, _ = emptyEvent(t, rawParams)
		r.Method = "POST"
	default:
		t.Fatal("Not implemented!")
	}
	r.URL.Path = path
	server.ServeHTTP(w, r)
	return w
}

func TestServeHTTP(t *testing.T) {
	server := newTestServer(t, "")
	for _, httpTest := range httpTests {
		w := serveRequest(t, server, httpTest.method, httpTest.path,
			httpTest.rawParams)

		expected := httpTest.responseBody
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
	method    string
	path      string
	rawParams string
	packet    string
}{
	// Valid requests
	{
		"GET", "/", "a=1&b=2",
		`{"t":"` + STATIC_ISO8601 + `","params":{"a":"1","b":"2"}}`,
	},
	{
		"POST", "/", `{"a": 1, "b": "2"}`,
		`{"t":"` + STATIC_ISO8601 + `","params":{"a":1,"b":"2"}}`,
	},
	// Invalid requests
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
			udpTest.rawParams)
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
