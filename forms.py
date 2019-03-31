from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired


class SettingsForm(FlaskForm):
    image_path = StringField('Image Path', validators=[DataRequired()])
    suspected_user = StringField('Suspected User', validators=[DataRequired()])
    classified_folder = StringField('Classified Data Folder', validators=[DataRequired()])
    es_host = StringField('ElasticSearch host name', validators=[DataRequired()])
    es_port = StringField('ElasticSearch port', validators=[DataRequired()])
    regripper_path = StringField('RegRipper Path', validators=[DataRequired()])
    virustotal_api_key = StringField('VirusTotal API key', validators=[DataRequired()])
    webshrinker_api_key = StringField('WebShrinker API key', validators=[DataRequired()])
    webshrinker_api_secret = StringField('WebShrinker API secret', validators=[DataRequired()])
    submit = SubmitField('Modify!')
