from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    priority = db.Column(db.Integer, nullable=False)
    due_date = db.Column(db.String(50), nullable=False)
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(minutes=30))

    return jsonify({'token': token})

@app.route('/todos', methods=['POST'])
@jwt_required()
def add_todo():
    data = request.get_json()
    new_todo = Todo(title=data['title'], description=data['description'], priority=data['priority'], due_date=data['due_date'], done=False, user_id=data['user_id'])

    db.session.add(new_todo)
    db.session.commit()

    return jsonify({'message': 'TODO added successfully'})

@app.route('/todos', methods=['GET'])
@jwt_required()
def get_todos():
    todos = Todo.query.all()
    output = []

    for todo in todos:
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['title'] = todo.title
        todo_data['description'] = todo.description
        todo_data['priority'] = todo.priority
        todo_data['due_date'] = todo.due_date
        todo_data['done'] = todo.done
        output.append(todo_data)

    return jsonify({'todos': output})

@app.route('/todos/<todo_id>', methods=['PUT'])
@jwt_required()
def update_todo(todo_id):
    data = request.get_json()
    todo = Todo.query.filter_by(id=todo_id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    todo.done = data['done']
    db.session.commit()

    return jsonify({'message': 'TODO updated successfully'})

@app.route('/todos/<todo_id>', methods=['DELETE'])
@jwt_required()
def delete_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id).first()

    if not todo:
        return jsonify({'message': 'No todo found!'})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'message': 'TODO deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)

