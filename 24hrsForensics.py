from app import app
import configparser


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('config.ini')
    app.run(host=config['GUI']['HOST'], port=config['GUI']['PORT'])

# to run the web app activate venv and run:
# export FLASK_APP=24hrsForensics.py
# flask run
