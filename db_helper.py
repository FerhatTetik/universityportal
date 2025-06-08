import sqlite3
import datetime
from typing import List, Dict, Any, Optional

class DatabaseHelper:
    def __init__(self, db_name: str = 'campus_portal.db'):
        self.db_name = db_name

    def get_connection(self):
        return sqlite3.connect(self.db_name)

    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def execute_update(self, query: str, params: tuple = ()) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount

    # Kullanıcı işlemleri
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        users = self.execute_query('SELECT * FROM users WHERE email = ?', (email,))
        return users[0] if users else None

    def get_all_users(self) -> List[Dict[str, Any]]:
        return self.execute_query('SELECT * FROM users ORDER BY created_at DESC')

    def create_user(self, name: str, email: str, password: str, role: str, avatar: str = None) -> int:
        query = '''
        INSERT INTO users (name, email, password, role, avatar, status, last_login)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        '''
        return self.execute_update(query, (name, email, password, role, avatar, datetime.datetime.now()))

    # Duyuru işlemleri
    def get_all_announcements(self) -> List[Dict[str, Any]]:
        return self.execute_query('''
            SELECT a.*, u.name as creator_name 
            FROM announcements a 
            LEFT JOIN users u ON a.created_by = u.id 
            ORDER BY a.publish_date DESC
        ''')

    def create_announcement(self, title: str, content: str, category: str, publish_date: str, created_by: int) -> int:
        query = '''
        INSERT INTO announcements (title, content, category, publish_date, status, created_by)
        VALUES (?, ?, ?, ?, 1, ?)
        '''
        return self.execute_update(query, (title, content, category, publish_date, created_by))

    # Haber işlemleri
    def get_all_news(self) -> List[Dict[str, Any]]:
        return self.execute_query('''
            SELECT n.*, u.name as creator_name 
            FROM news n 
            LEFT JOIN users u ON n.created_by = u.id 
            ORDER BY n.publish_date DESC
        ''')

    def create_news(self, title: str, content: str, image: str, category: str, publish_date: str, created_by: int) -> int:
        query = '''
        INSERT INTO news (title, content, image, category, publish_date, status, created_by)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        '''
        return self.execute_update(query, (title, content, image, category, publish_date, created_by))

    # Galeri işlemleri
    def get_all_gallery_items(self) -> List[Dict[str, Any]]:
        return self.execute_query('''
            SELECT g.*, u.name as creator_name 
            FROM gallery g 
            LEFT JOIN users u ON g.created_by = u.id 
            ORDER BY g.created_at DESC
        ''')

    def create_gallery_item(self, title: str, description: str, image: str, category: str, created_by: int) -> int:
        query = '''
        INSERT INTO gallery (title, description, image, category, status, created_by)
        VALUES (?, ?, ?, ?, 1, ?)
        '''
        return self.execute_update(query, (title, description, image, category, created_by))

    # Genel işlemler
    def update_status(self, table: str, item_id: int, status: bool) -> int:
        query = f'UPDATE {table} SET status = ? WHERE id = ?'
        return self.execute_update(query, (status, item_id))

    def delete_item(self, table: str, item_id: int) -> int:
        query = f'DELETE FROM {table} WHERE id = ?'
        return self.execute_update(query, (item_id,))

    def search_items(self, table: str, search_term: str, category: str = None, status: bool = None) -> List[Dict[str, Any]]:
        query = f'SELECT * FROM {table} WHERE title LIKE ?'
        params = [f'%{search_term}%']

        if category:
            query += ' AND category = ?'
            params.append(category)
        
        if status is not None:
            query += ' AND status = ?'
            params.append(status)

        query += ' ORDER BY created_at DESC'
        return self.execute_query(query, tuple(params)) 