"""Forms to manage Customers"""
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, ValidationError
from hashview.models import Customers

class CustomersForm(FlaskForm):
    """Class representing a customer Form"""
    name = StringField('Customer Name', validators=[DataRequired()])

    def validate_name(self, name):
        """Class function to validate customers name"""
        customer = Customers.query.filter_by(name = name.data).first()
        if customer:
            raise ValidationError('That customer already exists. Please choose a different one.')
