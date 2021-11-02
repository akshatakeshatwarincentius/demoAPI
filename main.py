from flask import Flask, request, Response, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
import datetime, requests, io, uuid, jwt
from deta import Deta

app = Flask(__name__)
#deta = Deta("c0afvv9a_LqHoTYCYC7Kq6pDTRUoeqo8thvoyufSD")  # configure your Deta project 
#drive = deta.Drive("database") # access to your drive
#drive.put("database.db", path="./database.db")

cors = CORS(app)
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY']= "secret"

import json

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    recipe = db.relationship('Recipe', backref='recipes', lazy=True)

    def register_user(_name, _password):
        user = Users.query.filter_by(name=_name).first()
        if user is None:
            hashed_password = generate_password_hash(_password, method='sha256')
            new_user = Users(public_id=str(uuid.uuid4()), name=_name, password=hashed_password, admin=False)
            db.session.add(new_user) 
            db.session.commit()  
            return jsonify(data={'message': 'registered successfully'}, ok=True)
        else:
            return jsonify(data={'message' :  'user already exists'}, ok=False)
        

    def get_user(_name):
        return Users.query.filter_by(name=_name).first()

    def get_users():
        users = Users.query.all()
        result = []
        for user in users:
            user_data = {}
            user_data['public_id'] = user.public_id
            user_data['name'] = user.name
            user_data['password'] = user.password
            user_data['admin'] = user.admin
            result.append(user_data)
        return result


# the class Recipe will inherit the db.Model of SQLAlchemy
class Recipe(db.Model):
    __tablename__ = 'recipe'  # creating a table name
    id = db.Column(db.Integer, primary_key=True)  # this is the primary key
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def json(self):
        return {'id': self.id, 'name': self.name, 'description': self.description, 'user_id': self.user_id}
        # this method we are defining will convert our output to json

    def add_recipe(_name, _description, _user_id):
        # creating an instance of our Recipe constructor
        new_recipe = Recipe(name=_name, description=_description, user_id=_user_id)
        db.session.add(new_recipe)  # add new recipe to database session
        db.session.commit()  # commit changes to session

    def get_all_recipes(_user_id):
        '''function to get all recipes in our database'''
        return [Recipe.json(recipe) for recipe in Recipe.query.filter_by(user_id=_user_id).all() ]

        
    def get_recipe(_id):
        '''function to get recipe using the id of the recipe as parameter'''
        return [Recipe.json(Recipe.query.filter_by(id=_id).first())]
        # recipe.json() coverts our output to the json format defined earlier
        # the filter_by method filters the query by the id
        # since our id is unique we will only get one result
        # the .first() method will get that first value returned

    def update_recipe(_id, _name, _description, _user_id):
        '''function to update the details of a recipe using the id, name,
        description and user_id as parameters'''
        recipe_to_update = Recipe.query.filter_by(id=_id).first()
        recipe_to_update.name = _name
        recipe_to_update.description = _description
        recipe_to_update.user_id = _user_id
        db.session.commit()

    def delete_recipe(_id):
        '''function to delete a recipe from our database using
           the id of the recipe as a parameter'''
        Recipe.query.filter_by(id=_id).delete()
        # filter recipe by id and delete
        db.session.commit()  # commiting the new change to our database



def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'x-access-tokens' in request.headers:
           token = request.headers['x-access-tokens']
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = Users.query.filter_by(public_id=data['public_id']).first()
       except:
           return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator

@app.route('/')
def index():
    return "Hello World"

@app.route('/database.db')
def database():
    url = "https://drive.deta.sh/v1/c0afvv9a/database/files/download?name=database.db"
    response = requests.get(url, headers={'X-Api-Key': 'c0afvv9a_LqHoTYCYC7Kq6pDTRUoeqo8thvoyufSD'})
    buffer = io.BytesIO()
    buffer.write(response.text.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     attachment_filename='database.db',
                     mimetype='text/csv')

@app.route('/login', methods=['POST'])
@cross_origin()
def login_user():
    try:        
        auth = request.get_json()  
        if not auth or not auth["name"] or not auth["password"]: 
            return jsonify(ok=False)   
    
        user = Users.get_user(auth["name"])
        if user != None:
            if check_password_hash(user.password, auth["password"]):
                token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, app.config['SECRET_KEY'], "HS256")
                return jsonify(data={'token' : token, 'logged_in': True, 'user_id': user.id}, ok=True)
        return jsonify(ok=False)
    except Exception as e:
        return jsonify(ok=False, error=str(e))

@app.route('/register', methods=['POST'])
@cross_origin()
def register_user(): 
    try:
        data = request.get_json()  
        res = Users.register_user(data['name'], data['password'])
        return res
    except Exception as e: 
        return jsonify(ok=False)

@app.route('/users', methods=['GET'])
@cross_origin()
#@token_required
def get_all_users(): #current_user 
   result = Users.get_users()  
   return jsonify({'users': result})

# route to get all recipes
@app.route('/recipes/<int:user_id>', methods=['GET'])
@cross_origin()
def get_recipes(user_id):
    '''Function to get all the recipes in the database'''
    return jsonify({'Recipes': Recipe.get_all_recipes(user_id)})

# route to add new recipe
@app.route('/recipe', methods=['POST'])
@cross_origin()
def add_recipe():
    '''Function to add new recipe to our database'''
    request_data = request.get_json()  # getting data from client
    Recipe.add_recipe(request_data["name"], request_data["description"],
                    request_data["user_id"])
    response = Response("Recipe added", 201, mimetype='application/json')
    return response

# route to view single recipe with GET method
@app.route('/recipe/<int:id>', methods=['GET'])
@cross_origin()
def get_recipe(id):
    '''Function to get recipe from our database using recipe id'''
    
    return jsonify({'Recipe': Recipe.get_recipe(id)})

# route to update recipe with PUT method
@app.route('/recipe/<int:id>', methods=['PUT'])
@cross_origin()
def update_recipe(id):
    '''Function to edit recipe in our database using recipe id'''
    request_data = request.get_json()
    Recipe.update_recipe(id, request_data['name'], request_data['description'],request_data['user_id'])
    response = Response("Recipe Updated", status=200, mimetype='application/json')
    return response

# route to delete recipe using the DELETE method
@app.route('/recipe/<int:id>', methods=['DELETE'])
@cross_origin()
def remove_recipe(id):
    '''Function to delete recipe from our database'''
    Recipe.delete_recipe(id)
    response = Response("Recipe Deleted", status=200, mimetype='application/json')
    return response

app.run(host="0.0.0.0", port="5000", debug=True)