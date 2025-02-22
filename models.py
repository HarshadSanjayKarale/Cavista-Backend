# models.py
from mongoengine import Document, StringField, ListField, ReferenceField, connect

# Connect to the MongoDB database
connect('auth_db')

class Reply(Document):
    comment_id = StringField(required=True)
    user_id = StringField(required=True)
    username = StringField(required=True)
    content = StringField(required=True)

class Comment(Document):
    post_id = StringField(required=True)
    user_id = StringField(required=True)
    username = StringField(required=True)
    content = StringField(required=True)
    replies = ListField(ReferenceField(Reply))