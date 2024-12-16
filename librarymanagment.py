# Full-Stack Library Management System

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import date

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    isbn = db.Column(db.String(13), unique=True, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    issue_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date, nullable=True)
    fine = db.Column(db.Float, default=0.0)

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data.get('name') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(name=data['name'], email=data['email'], password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'id': user.id, 'is_admin': user.is_admin})
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/books', methods=['GET', 'POST'])
@jwt_required()
def manage_books():
    identity = get_jwt_identity()
    if request.method == 'POST':
        if not identity['is_admin']:
            return jsonify({'message': 'Admin privileges required'}), 403

        data = request.json
        if not data.get('title') or not data.get('author') or not data.get('isbn') or not data.get('quantity'):
            return jsonify({'message': 'Missing required fields'}), 400

        if Book.query.filter_by(isbn=data['isbn']).first():
            return jsonify({'message': 'Book with this ISBN already exists'}), 400

        book = Book(title=data['title'], author=data['author'], isbn=data['isbn'], quantity=data['quantity'])
        db.session.add(book)
        db.session.commit()
        return jsonify({'message': 'Book added successfully!'}), 201

    books = Book.query.all()
    return jsonify([{
        'id': book.id,
        'title': book.title,
        'author': book.author,
        'isbn': book.isbn,
        'quantity': book.quantity
    } for book in books]), 200

@app.route('/issue', methods=['POST'])
@jwt_required()
def issue_book():
    data = request.json
    identity = get_jwt_identity()

    if not data.get('book_id'):
        return jsonify({'message': 'Book ID is required'}), 400

    book = Book.query.get(data['book_id'])
    if not book or book.quantity <= 0:
        return jsonify({'message': 'Book not available'}), 400

    transaction = Transaction(user_id=identity['id'], book_id=book.id, issue_date=date.today())
    book.quantity -= 1

    db.session.add(transaction)
    db.session.commit()
    return jsonify({'message': 'Book issued successfully!'}), 200

@app.route('/return', methods=['POST'])
@jwt_required()
def return_book():
    data = request.json

    if not data.get('transaction_id'):
        return jsonify({'message': 'Transaction ID is required'}), 400

    transaction = Transaction.query.get(data['transaction_id'])
    if not transaction or transaction.return_date is not None:
        return jsonify({'message': 'Invalid transaction'}), 400

    transaction.return_date = date.today()
    transaction.fine = max(0, (transaction.return_date - transaction.issue_date).days - 14) * 1.0

    book = Book.query.get(transaction.book_id)
    book.quantity += 1

    db.session.commit()
    return jsonify({'message': 'Book returned successfully!', 'fine': transaction.fine}), 200

# Initialize DB
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
