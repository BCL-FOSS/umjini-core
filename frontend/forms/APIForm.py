from quart_wtf import QuartForm
from wtforms import SubmitField, StringField
from wtforms.validators import DataRequired, Length

class APIForm(QuartForm):
    user_id = StringField("User ID", validators=[DataRequired(), Length(max=30)])
    chat_id = StringField("Chat ID", validators=[DataRequired(), Length(max=30)])
    submit = SubmitField('Save')
        
       

