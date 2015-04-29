# pixel

[![Build Status](https://travis-ci.org/hblanks/pixel.svg?branch=master)](https://travis-ci.org/hblanks/pixel)

pixel is a simple server for serving tracking pixels and logging them
to a downstream consumer. For starters, it just logs to UDP syslog
using go's `log/syslog` package.


## Setup

To install for development, just do:

    go install github.com/hblanks/pixel/...

A directory to simplify debian packaging is forthcoming.


## Usage & sample requests

pixel is configured from the environment. A typical invocation might
be:

    LISTEN_ADDRESS=:8080 pixel


pixel serves tracks both pixel GET:

    curl http://localhost:8080/trk/v1.gif?a=b&foo=c

and JSON POST:

    curl -d '{"a": "b", "foo": "c"}' http://localhost:8080/trk/v1

HTTP requests for any path.


## Quickstart (configured with nginx)

Configure pixel to run using the supervisor / container of your choice
(runit, upstart, daemontools, docker, etc.)

When paired with nginx, a typical (and verified) nginx configuration
might be:

    http {
        gzip on;
        
        server {
            listen 80 default_server;
            
            location /trk/ {
                proxy_pass http://localhost:8080/;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }
            
            location / {
                // Some other app
                proxy_pass http://localhost:5555/;
                proxy_read_timeout 300;
            }
        }
    }


When paired with syslog-ng (and you'll either be pairing with syslog-ng
or rsyslog), a typical (and verified) syslog-ng configuration might be:


    source s_local_udp {
        udp(
            ip(127.0.0.1)
            port(514)
        );
    };


    destination d_hourly {
        file(
            "/var/log/hourly/$PROGRAM-$YEAR$MONTH${DAY}T${HOUR}00Z-${HOST}.log"
            create_dirs(yes)
            template("$ISODATE $HOST $PROGRAM $MSG\n")
        );
    };


    filter f_valid_program {
        # Exclude program fields that have slashes in them
        program(^[^/]+$);
    };


    log {
        source(s_local_udp);
        filter(f_valid_program);
        destination(d_hourly);
    };

If you do choose to have hourly logs, you may also want to use
[logjam](https://github.com/hblanks/logjam) to compress and upload them
regularly to S3. (Of course, you could also easily forward your logs
from your local syslog-ng upstream using some TCP/TLS transport.)


## Development

`go test ./...` will run all tests.

`LISTEN_ADDRESS=:8080 SYSLOG_ADDRESS=127.0.0.1:5140 pixel` will run
pixel and have it send UDP packets to 127.0.0.01:5140.

`LISTEN_ADDRESS=127.0.0.1:5140 syslog-receive` (included in this repo)
will listen on the same syslog IP:port and print UDP packets as they
come in.

## A word on log/syslog

Go's `log/syslog` sends messages to syslog in
[RFC 3164](https://tools.ietf.org/html/rfc3164) format. A sample
log message, which you can capture using the accompanying
`syslog-receive` utility, thus looks like:

    <190>2015-03-24T20:49:41Z web-localdev pixel[6288]: {"t":"2015-03-24T20:49:41Z","params":{"q":"2b=3"},"ua":"curl/7.22.0 (x86_64-pc-linux-gnu) libcurl/7.22.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 librtmp/2.3","ip":"128.24.19.19"}

Both `syslog-ng` and `rsyslog` will parse such messages with no
difficulties.
