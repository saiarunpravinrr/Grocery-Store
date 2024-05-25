from flask import Blueprint,jsonify,request
from app1.models import User

auth_bp =Blueprint('auth',__name__)

@auth_bp.post('/register')
def register_user():
    
    data=request.get_json()
    
    user=User.get_user_by_username(username=data.get('username'))
    
    if user is not None:
        return jsonify({'error'}),409
    
    new_user=User(
        username=data.get('username'),
        email=data.get('email')
    )