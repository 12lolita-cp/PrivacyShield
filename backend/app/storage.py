"""MongoDB-backed data store with a local SQLite development fallback."""
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.getenv('DATABASE_PATH', str(ROOT / 'privacyshield.sqlite3')))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_uri = os.getenv('MONGODB_URI', '').strip()
_mongo = None
if _uri:
    try:
        client = MongoClient(_uri, serverSelectionTimeoutMS=2000)
        client.admin.command('ping')
        _mongo = client[os.getenv('MONGODB_DATABASE', 'privacyshield')]
        _mongo.users.create_index('email', unique=True)
    except Exception as exc:
        print(f'WARNING: MongoDB unavailable; using local SQLite. Reason: {exc}')
        _mongo = None


def conn():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init():
    if _mongo is not None:
        return
    with conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, filename TEXT NOT NULL, risk INTEGER, findings TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS urls (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, url TEXT NOT NULL, score INTEGER, level TEXT, reasons TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS exposures (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, service TEXT NOT NULL, categories TEXT NOT NULL, notes TEXT, created_at TEXT);
        ''')


def one_user(email):
    if _mongo is not None:
        u = _mongo.users.find_one({'email': email.lower()}, {'_id': 0})
        return u
    with conn() as c:
        row = c.execute('SELECT * FROM users WHERE email=?', (email.lower(),)).fetchone()
        return dict(row) if row else None


def create_user(user):
    if _mongo is not None:
        _mongo.users.insert_one(dict(user))
        return
    with conn() as c:
        c.execute('INSERT INTO users(id,email,name,password_hash) VALUES(?,?,?,?)', (user['id'], user['email'], user['name'], user['password_hash']))


def insert(collection, item):
    obj = dict(item)
    obj.setdefault('created_at', datetime.now(timezone.utc).isoformat())
    if _mongo is not None:
        _mongo[collection].insert_one(dict(obj))
    else:
        columns = list(obj)
        with conn() as c:
            c.execute(f"INSERT INTO {collection} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", [obj[x] for x in columns])
    return obj


def list_for(collection, user_id):
    if _mongo is not None:
        return list(_mongo[collection].find({'user_id': user_id}, {'_id': 0}).sort('created_at', -1).limit(100))
    with conn() as c:
        return [dict(r) for r in c.execute(f'SELECT * FROM {collection} WHERE user_id=? ORDER BY created_at DESC LIMIT 100', (user_id,))]


def delete_exposure(item_id, user_id):
    if _mongo is not None:
        return _mongo.exposures.delete_one({'id': item_id, 'user_id': user_id}).deleted_count > 0
    with conn() as c:
        cur = c.execute('DELETE FROM exposures WHERE id=? AND user_id=?', (item_id, user_id))
        return cur.rowcount > 0
