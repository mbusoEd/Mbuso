from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
import os
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Mbuso2012!'

# Configure SQL Server connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://DESKTOP-F000UK9/SalesBudgetDB?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Login Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    entity_id = db.Column(db.Integer, db.ForeignKey('entity.id'))


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Middleware to check JWT tokens
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/login-page')
def login_page():
    return render_template('login.html')

# User Login
@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form  # Handle form submissions

    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode(
            {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        db.session.add(LoginLog(username=user.username, status='Success'))
        db.session.commit()
        return jsonify({'token': token})
    else:
        db.session.add(LoginLog(username=data['username'], status='Failed'))
        db.session.commit()
        return jsonify({'message': 'Invalid credentials'}), 401


# Get Entities based on user role
#@app.route('/entities', methods=['GET'])
#@token_required
#def get_entities(current_user):
   # if current_user.role == 'admin':
     #   entities = Entity.query.all()
    #else:
       # entities = Entity.query.filter_by(id=current_user.entity_id).all()
    #return jsonify([{'id': e.id, 'name': e.name} for e in entities])

# Assign Users to Entities (Admin Only)
@app.route('/assign-user', methods=['POST'])
@token_required
def assign_user(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403
    data = request.get_json()
    user = User.query.filter_by(id=data['user_id']).first()
    if user:
        user.entity_id = data['entity_id']
        db.session.commit()
        return jsonify({'message': 'User assigned successfully'})
    return jsonify({'message': 'User not found'}), 404

# Define database model
class SalesData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entity_id = db.Column(db.Integer, db.ForeignKey('entity.id'), nullable=False)
    entity = db.relationship('Entity', back_populates='sales_data')  # Explicit relationship
    
    lineofbusiness = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(20), nullable=False)
    measurement = db.Column(db.String(20), nullable=False)
    october = db.Column(db.Float, nullable=False)
    november = db.Column(db.Float, nullable=False)
    december = db.Column(db.Float, nullable=False)
    january = db.Column(db.Float, nullable=False)
    february = db.Column(db.Float, nullable=False)
    march = db.Column(db.Float, nullable=False)
    april = db.Column(db.Float, nullable=False)
    may = db.Column(db.Float, nullable=False)
    june = db.Column(db.Float, nullable=False)
    july = db.Column(db.Float, nullable=False)
    august = db.Column(db.Float, nullable=False)
    september = db.Column(db.Float, nullable=False)


class Entity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    sales_data = db.relationship('SalesData', back_populates='entity', cascade="all, delete-orphan")  


class LineOfBusiness(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Measurement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/config-page')
def config_page():
    return render_template('config.html')

@app.route('/sales-data')
def sales_data_json():
    data = SalesData.query.all()
    return jsonify([{column.name: getattr(row, column.name) for column in row.__table__.columns} for row in data])

@app.route('/sales-data/view')
def sales_data_html():
    data = SalesData.query.all()
    return render_template('salesbud.html', sales_data=data)

@app.route('/get-entities', methods=['GET'])
def get_entities():
    entities = Entity.query.with_entities(Entity.id, Entity.name).all()
    return jsonify([{"id": e.id, "name": e.name} for e in entities])

@app.route('/get-lob', methods=['GET'])
def get_lob():
    lob_list = LineOfBusiness.query.with_entities(LineOfBusiness.id, LineOfBusiness.name).all()
    return jsonify([{"id": lob.id, "name": lob.name} for lob in lob_list])

@app.route('/get-categories', methods=['GET'])
def get_categories():
    categories = Category.query.with_entities(Category.id, Category.name).all()
    return jsonify([{"id": cat.id, "name": cat.name} for cat in categories])

@app.route('/get-UOM', methods=['GET'])
def get_uom():
    uoms = Measurement.query.with_entities(Measurement.id, Measurement.name).all()
    return jsonify([{"id": uom.id, "name": uom.name} for uom in uoms])

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if file and file.filename.endswith('.xlsx'):
        df = pd.read_excel(file)
        for _, row in df.iterrows():
            existing_record = SalesData.query.filter_by(entity_id=row["entity_id"], lineofbusiness=row["lineofbusiness"]).first()
            if existing_record:
                for key, value in row.items():
                    setattr(existing_record, key, value)
            else:
                new_record = SalesData(**row.to_dict())
                db.session.add(new_record)
        db.session.commit()
        return "File uploaded successfully"
    return "Invalid file format", 400

@app.route('/update-sales-data', methods=['PUT'])
def update_sales_data():
    data = request.json
    record = SalesData.query.get(data['id'])
    if record:
        setattr(record, data['column'], data['value'])
        db.session.commit()
        return jsonify({"message": "Update successful"}), 200
    return jsonify({"message": "Record not found"}), 404

@app.route('/add-sales-data', methods=['POST'])
def add_sales_data():
    data = request.json
    new_record = SalesData(**data)
    db.session.add(new_record)
    db.session.commit()
    return jsonify({"message": "Record added successfully", "id": new_record.id}), 201

@app.route('/delete-sales-data/<int:id>', methods=['DELETE'])
def delete_sales_data(id):
    record = SalesData.query.get(id)
    if record:
        db.session.delete(record)
        db.session.commit()
        return jsonify({"message": "Record deleted successfully"}), 200
    return jsonify({"message": "Record not found"}), 404

@app.route('/get-config/<table_name>')
def get_config(table_name):
    models = {'entities': Entity, 'linesofbusiness': LineOfBusiness, 'categories': Category, 'measurements': Measurement}
    model = models.get(table_name)
    if model:
        data = model.query.all()
        return jsonify([{column.name: getattr(row, column.name) for column in row.__table__.columns} for row in data])
    return jsonify({"message": "Invalid table name"}), 400

@app.route('/add-config/<table_name>', methods=['POST'])
def add_config(table_name):
    models = {'entities': Entity, 'linesofbusiness': LineOfBusiness, 'categories': Category, 'measurements': Measurement}
    model = models.get(table_name)
    if model:
        data = request.json
        new_record = model(**data)
        db.session.add(new_record)
        db.session.commit()
        return jsonify({"message": "Record added successfully"}), 201
    return jsonify({"message": "Invalid table name"}), 400

@app.route('/delete-config/<table_name>/<int:id>', methods=['DELETE'])
def delete_config(table_name, id):
    models = {'entities': Entity, 'linesofbusiness': LineOfBusiness, 'categories': Category, 'measurements': Measurement}
    model = models.get(table_name)
    if model:
        record = model.query.get(id)
        if record:
            db.session.delete(record)
            db.session.commit()
            return jsonify({"message": "Record deleted successfully"}), 200
        return jsonify({"message": "Record not found"}), 404
    return jsonify({"message": "Invalid table name"}), 4000

@app.route('/edit-config/<table_name>/<int:id>', methods=['PUT'])
def edit_config(table_name, id):
    models = {
        'entities': Entity,
        'linesofbusiness': LineOfBusiness,
        'categories': Category,
        'measurements': Measurement,
        'suppliers': Supplier
    }
    model = models.get(table_name)
    if model:
        record = model.query.get(id)
        if record:
            data = request.json
            record.name = data.get("name")
            db.session.commit()
            return jsonify({"message": "Record updated successfully"}), 200
        return jsonify({"message": "Record not found"}), 404
    return jsonify({"message": "Invalid table name"}), 400

@app.route('/get-sales-data', methods=['GET'])
def get_sales_data():
    sales_data = SalesData.query.all()
    
    return jsonify([
        {
            "id": record.id,
            "entity_name": Entity.query.get(record.entity_id).name if record.entity_id else "N/A",
            "lineofbusiness": LineOfBusiness.query.get(record.lineofbusiness).name if record.lineofbusiness else "N/A",
            "category": Category.query.get(record.category).name if record.category else "N/A",
            "measurement": Measurement.query.get(record.measurement).name if record.measurement else "N/A",
            "october": record.october,
            "november": record.november,
            "december": record.december,
            "january": record.january,
            "february": record.february,
            "march": record.march,
            "april": record.april,
            "may": record.may,
            "june": record.june,
            "july": record.july,
            "august": record.august,
            "september": record.september
        } for record in sales_data
    ])



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
