from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserDBModelView, AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
from datetime import datetime
from dotenv import load_dotenv
import os
import jwt

# Load environment variables from .env file
load_dotenv()
class JWTDecoder:
    def __init__(self, secret_key, algorithm = 'HS256'):
        self.secret_key = secret_key
        self.algorithm  = algorithm

    def decode_token(self, token):
        try:
            # Decode and verify the token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception("Token has expired")
        except jwt.InvalidTokenError as e:
            raise Exception(f"Invalid token: {str(e)}")


class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        authsuccess  = False
        token        = ''
        redirect_url = self.appbuilder.get_url_for_index
        user         = None
        
        if request.args.get('redirect') is not None:
            redirect_url = request.args.get('redirect')

        if request.args.get('token') is not None:
            token = request.args.get('token')
            
        # This should match your Laravel JWT_SECRET
        JWT_SECRET    = os.getenv('JWT_SECRET_KEY')
        JWT_ALGORITHM = os.getenv('JWT_ALGORITHM')
        
        decoder = JWTDecoder(secret_key=JWT_SECRET, algorithm=JWT_ALGORITHM)
    
        try:
            decoded_payload = decoder.decode_token(token)
            # Accessing specific claims
            username = decoded_payload.get('username')
            email    = decoded_payload.get('email')
                            
            user = self.appbuilder.sm.find_user(email=email)
            
            if user != None:
                authsuccess = True
            
        except Exception as e:
            flash(f"{e}", 'warning')
            return super().login()

        if g.user is not None and g.user.is_authenticated and not authsuccess:
            return redirect(redirect_url)

        if authsuccess:
            login_user(user, remember=False)
            return redirect(redirect_url)
        else:
            flash('Auto Login Failed', 'warning')
            return super().login()


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView

    def __init__(self, appbuilder):
        super().__init__(appbuilder)