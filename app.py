from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from db_helper import DatabaseHelper
import hashlib
import os
from werkzeug.utils import secure_filename
import sqlite3

app = Flask(__name__)
CORS(app)
db = DatabaseHelper()

# Dosya yükleme ayarları
UPLOAD_FOLDER = 'images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return f'images/{filename}'
    return None

def get_db_connection():
    conn = sqlite3.connect('campus_portal.db')
    conn.row_factory = sqlite3.Row
    return conn

# Kullanıcı işlemleri
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = db.get_user_by_email(data['email'])
    
    if user and user['password'] == hashlib.sha256(data['password'].encode()).hexdigest():
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'role': user['role']
            }
        })
    return jsonify({'success': False, 'message': 'Geçersiz e-posta veya şifre'})

@app.route('/api/users', methods=['GET'])
def get_users():
    users = db.get_all_users()
    return jsonify({'success': True, 'users': users})

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    user_id = db.create_user(
        data['name'],
        data['email'],
        hashlib.sha256(data['password'].encode()).hexdigest(),
        data['role'],
        data.get('avatar')
    )
    return jsonify({'success': True, 'user_id': user_id})

# Duyuru işlemleri
@app.route('/api/announcements', methods=['GET'])
def get_announcements():
    announcements = db.get_all_announcements()
    return jsonify({'success': True, 'announcements': announcements})

@app.route('/api/announcements', methods=['POST'])
def create_announcement():
    data = request.json
    announcement_id = db.create_announcement(
        data['title'],
        data['content'],
        data['category'],
        data['publish_date'],
        data['created_by']
    )
    return jsonify({'success': True, 'announcement_id': announcement_id})

# Haber işlemleri
@app.route('/api/news', methods=['GET'])
def get_news():
    news = db.get_all_news()
    return jsonify({'success': True, 'news': news})

@app.route('/api/news', methods=['POST'])
def create_news():
    data = request.json
    image_path = save_file(request.files.get('image'))
    if not image_path:
        return jsonify({'success': False, 'message': 'Geçersiz görsel dosyası'})
    
    news_id = db.create_news(
        data['title'],
        data['content'],
        image_path,
        data['category'],
        data['publish_date'],
        data['created_by']
    )
    return jsonify({'success': True, 'news_id': news_id})

# Galeri işlemleri
@app.route('/api/gallery', methods=['GET'])
def get_gallery():
    gallery_items = db.get_all_gallery_items()
    return jsonify({'success': True, 'gallery': gallery_items})

@app.route('/api/gallery', methods=['POST'])
def create_gallery_item():
    data = request.json
    image_path = save_file(request.files.get('image'))
    if not image_path:
        return jsonify({'success': False, 'message': 'Geçersiz görsel dosyası'})
    
    gallery_id = db.create_gallery_item(
        data['title'],
        data.get('description', ''),
        image_path,
        data['category'],
        data['created_by']
    )
    return jsonify({'success': True, 'gallery_id': gallery_id})

# Genel işlemler
@app.route('/api/<table>/<int:item_id>/status', methods=['PUT'])
def update_status(table, item_id):
    data = request.json
    result = db.update_status(table, item_id, data['status'])
    return jsonify({'success': result > 0})

@app.route('/api/<table>/<int:item_id>', methods=['DELETE'])
def delete_item(table, item_id):
    result = db.delete_item(table, item_id)
    return jsonify({'success': result > 0})

@app.route('/api/<table>/search', methods=['GET'])
def search_items(table):
    search_term = request.args.get('q', '')
    category = request.args.get('category')
    status = request.args.get('status')
    if status is not None:
        status = status.lower() == 'true'
    
    items = db.search_items(table, search_term, category, status)
    return jsonify({'success': True, 'items': items})

@app.route('/')
def index():
    conn = get_db_connection()
    
    # Kullanıcıları al
    users = conn.execute('SELECT * FROM users').fetchall()
    
    # Duyuruları al
    announcements = conn.execute('SELECT * FROM announcements').fetchall()
    
    # Haberleri al
    news = conn.execute('SELECT * FROM news').fetchall()
    
    # Galeri görsellerini al
    gallery = conn.execute('SELECT * FROM gallery').fetchall()
    
    conn.close()
    
    return render_template('index.html', 
                         users=users, 
                         announcements=announcements, 
                         news=news, 
                         gallery=gallery)

if __name__ == '__main__':
    # Upload klasörünü oluştur
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True) 