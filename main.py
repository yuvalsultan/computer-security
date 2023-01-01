# main function
# create_app is defined in __init__.py

from website import create_app
from flask import session

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
