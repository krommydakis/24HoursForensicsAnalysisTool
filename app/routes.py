from app import app
from flask import render_template, redirect, request
from report import report
from forms import SettingsForm
import configparser


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route("/report")
def chart():
    values = report()
    if type(values) == str:
        return values
    else:
        return render_template('report.html', values=values.values(),)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    form = SettingsForm(request.form)
    if request.method == 'GET':
        config = configparser.ConfigParser()
        config.read('config.ini')
        form.image_path.data = config['DEFAULT']['IMAGE_PATH']
        form.suspected_user.data = config['DEFAULT']['SUSPECTED_USER']
        form.classified_folder.data = config['DEFAULT']['CLASSIFIED_DATA_FOLDER']
        form.es_host.data = config['ELASTIC_SEARCH']['HOST']
        form.es_port.data = config['ELASTIC_SEARCH']['PORT']
        form.regripper_path.data = config['3RD_PARTY']['REGRIPPER_PATH']
        form.virustotal_api_key.data = config['3RD_PARTY']['VIRUSTOTAL_API_KEY']
        form.webshrinker_api_key.data = config['3RD_PARTY']['WEBSHRINKER_API_KEY']
        form.webshrinker_api_secret.data = config['3RD_PARTY']['WEBSHRINKER_API_SECRET']

    if request.method == 'POST' and form.validate():
        config = configparser.ConfigParser()
        config['DEFAULT'] = {}
        config['DEFAULT']['IMAGE_PATH'] = form.image_path.data
        config['DEFAULT']["SUSPECTED_USER"] = form.suspected_user.data
        config['DEFAULT']["CLASSIFIED_DATA_FOLDER"] = form.classified_folder.data
        config['ELASTIC_SEARCH'] = {}
        config['ELASTIC_SEARCH']['HOST'] = form.es_host.data
        config['ELASTIC_SEARCH']['PORT'] = form.es_port.data
        config['3RD_PARTY'] = {}
        config['3RD_PARTY']["REGRIPPER_PATH"] = form.regripper_path.data
        config['3RD_PARTY']["VIRUSTOTAL_API_KEY"] = form.virustotal_api_key.data
        config['3RD_PARTY']["WEBSHRINKER_API_KEY"] = form.webshrinker_api_key.data
        config['3RD_PARTY']["WEBSHRINKER_API_SECRET"] = form.webshrinker_api_secret.data
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        return redirect('/')

    return render_template('settings.html', title='Settings', form=form)
