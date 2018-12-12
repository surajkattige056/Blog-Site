#!/usr/bin/python3

from server import app

if __name__ == "__main__":
    app.run('0.0.0.0', 5000, ssl_context=('/etc/ssl/certs/server_cert.crt', '/etc/ssl/private/server_key.key'))
