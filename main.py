# main function
# create_app is defined in __init__.py
import ssl
import socket
from website import create_app
from flask import session

app = create_app()

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('./CAPrivate.pem')
    # context.load_cert_chain('./cert.pem', './key.pem')

    context.load_cert_chain('./server.crt', './server.key')
    app.run(debug=True,ssl_context=context)
