# pixel

pixel is a simple server for serving tracking pixels and logging them
to a downstream consumer. For starters, it just logs to UDP syslog.

## Setup

To install for development, just do:

    go install github.com/hblanks/pixel/...

A directory to simplify debian packaging is forthcoming.

## Usage

pixel is configured from the environment. A typical invocation might
be:

    LISTEN_ADDRESS=:8000 pixel

## Quickstart (with nginx)

A typical nginx configuration might be:

    http {
        gzip on;
        
        server {
            listen 80 default_server;
            
            location /trk/ {
                proxy_pass http://localhost:8000/;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto "http";
            }
            
            location / {
                // Some other app
                proxy_pass http://localhost:5555/;
                proxy_read_timeout 300;
            }
        }
    }
    