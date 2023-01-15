# main function
# create_app is defined in __init__.py
import ssl
import socket
from website import create_app
from flask import session

app = create_app()

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('./cert.pem', './key.pem')
    app.run(debug=True,ssl_context=context)
