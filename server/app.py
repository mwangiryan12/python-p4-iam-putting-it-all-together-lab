#!/usr/bin/env python3

from flask import request, session,make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def authorize_user():
    if not session.get('user_id') and request.endpoint == "recipes":
        return make_response({'error':"Unauthorized"},401)

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        
        try:
            user = User(
                username = username,
                image_url = image_url,
                bio = bio
            )
            user.password_hash = password

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except Exception as e:

            return {'error': e.args}, 422
        

class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        if user:
            response = make_response(user.to_dict(),200)
            return response
        else:
            return make_response({"error":"Unauthorized"},401)

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username = data.get('username')).first()
        if user:
            if user.authenticate(data.get('password')):
                session['user_id'] = user.id
                response = make_response(user.to_dict(),200)
                return response
        else:
            return make_response({'error':"Unauthorized"},401)

class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return make_response({},204)
        else:
            return make_response({'error':"Unauthorized"},401)


class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        return [recipe.to_dict() for recipe in user.recipes], 200
    
    def post(self):
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')
        user_id = session.get('user_id')

        try:
            recipe = Recipe(
                title = title,
                instructions = instructions,
                minutes_to_complete = minutes_to_complete,
                user_id = user_id
                )
            db.session.add(recipe)
            db.session.commit()

            response = make_response(recipe.to_dict(),201)
            return response
        except Exception as e:
            return make_response({'errors':[e.args]},422)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
