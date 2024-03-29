from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, Length, EqualTo, regexp

import re


# Function to check phone number is of format (0000-000-0000)
def validate_phone(self, StringField):
    p = re.compile(r"\d{4}[-]\d{3}[-]\d{4}$")
    if not p.match(StringField.data):
        raise ValidationError("Please enter a phone number using a valid format (0000-000-0000)")


# Function to check user data against excluded characters
def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed")


class RegisterForm(FlaskForm):
    # Displays fields for user information with appropriate validators
    email = StringField(validators=[DataRequired(), Email("Please enter a valid email address.")])
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    phone = StringField(validators=[DataRequired(), validate_phone])

    # Displays field for password with appropriate validators to ensure good password strength and integrity
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12),
                                         regexp(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{6,}$',
                                                message="Password must include the following:"
                                                        " at least 1 digit,"
                                                        " at least 1 lowercase word character,"
                                                        " at least 1 uppercase word character,"
                                                        " at least 1 special character")])

    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password',
                                                                         message="Password must match field above")])
    submit = SubmitField()


# Displays fields for logging a user in including captcha
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired(), Length(min=6, max=6)])
    recaptcha = RecaptchaField()

    submit = SubmitField()
