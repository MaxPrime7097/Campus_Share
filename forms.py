from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6)])
    filiere = StringField('Filière', validators=[DataRequired()])
    niveau = StringField('Niveau', validators=[DataRequired()])
    submit = SubmitField('S\'inscrire')