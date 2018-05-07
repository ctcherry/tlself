# tlself

Lightweight, dynamic, and easy local HTTPS web development

## Requirements

* OSX

## How?

First, tlself creates a self-signed certificate authority. This newly created CA is added to the list of trusted cert roots on the system. This means that if that CA is used to sign some other TLS cert, it will be trusted, and not result in a warning in your local web browsers.

tlself then starts a TCP proxy that listens on localhost:443 and, using SNI, dynamically creates TLS certificates for incoming requests signed by the trusted self signed root. Each request is them proxied to localhost:80, which is where your local development server can be listening. This results in any local development domain you are using showing as HTTPS trusted in the browser.

## Configuration

Both the listening and backend TCP connections are configurable.

* `LISTEN` - The IP address and port that the proxy should listen on to make TLS connections, default is 127.0.0.1:443
* `BACKEND` - The IP address and port that the proxy should send incoming unencrypted connections to, default is 127.0.0.1:80
