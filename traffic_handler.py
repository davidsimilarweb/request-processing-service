import json
import urllib.parse
import requests
from mitmproxy import http
from appstoretoken import AppStoreToken
import os
from datetime import datetime, timedelta
import sqlite3
import time
TOKEN_EXTRACTABLE_HOSTS = [
    'amp-api-edge.apps.apple.com',
    'amp-api.apps.apple.com'
]
SAVE_BODY_HOSTS = [
    'amp-api-edge.apps.apple.com',
    'amp-api.apps.apple.com'
]
API_URL = os.getenv("IOS_SDK_SERVER_URL")
API_TOKEN = os.getenv("IOS_SDK_SERVER_TOKEN")

KEEP_LOGS_MINUTES = int(os.getenv("KEEP_LOGS_MINUTES") or 10)
def sync_token(token: AppStoreToken):
    headers = { 'X-Token': API_TOKEN }
    url = API_URL + 'update-tokens'
    # logging.info(f"Sending request to {url} with {len(tokens)} tokens...")
    response = requests.post(url, json=token.json(),headers=headers)
    # logging.info(f'Got response: {response.status_code}')
    return response.status_code == 200

def process_token(flow: http.HTTPFlow, host: str, ip: str):
    token = AppStoreToken(ip,host, flow.request.headers.get('authorization'))
    key = f"{ip}@{host}"
    if key not in token_map or token_map[key] is None:
        token_map[key] = token
    else:
        if token_map[key].token == token.token:
            return
        token_map[key].token = token
    sync_token(token.augment())

def response(flow: http.HTTPFlow):

    ip = None
    if flow.client_conn and flow.client_conn.address:
        ip = flow.client_conn.address[0]
    host = urllib.parse.urlparse(flow.request.url).hostname


    if host in TOKEN_EXTRACTABLE_HOSTS:
        process_token(flow, host, ip)

    
    request_data = {
        "timestamp": flow.request.timestamp_start,
        "method": flow.request.method,
        "url": flow.request.url,
        "host": host,
        "ip": ip,
        "http_version": flow.request.http_version,
        "headers": dict(flow.request.headers),
    }
    response_data = {
        "timestamp": flow.response.timestamp_start,
        "status_code": flow.response.status_code,
        "reason": flow.response.reason,
        "http_version": flow.response.http_version,
        "headers": dict(flow.response.headers),
    }

    if host in SAVE_BODY_HOSTS:
        try:
            content = flow.request.get_text(strict=False) if flow.request.content else ""
        except Exception:
            content = "[binary data]"
        request_data['body'] = content

        try:
            content = flow.response.get_text(strict=False) if flow.response.content else ""
        except Exception:
            content = "[binary data]"
        response_data['body'] = content

    full_flow = {
        "request": request_data,
        "response": response_data,
    }

    insert_log(conn,full_flow)
    cleanup_old_entries(conn, KEEP_LOGS_MINUTES)


def setup_db(db_path='traffic.db'):
    """
    Set up the SQLite database and create the logs table with separate fields for
    request and response data.
    """
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            host TEXT,
            url TEXT,
            method TEXT,
            status_code INTEGER,
            reason TEXT,
            request_timestamp REAL,
            response_timestamp REAL,
            request_http_version TEXT,
            response_http_version TEXT,
            request_headers TEXT,
            response_headers TEXT,
            request_body TEXT,
            response_body TEXT
        )
    ''')
    conn.commit()
    return conn

def insert_log(conn, full_flow):
    c = conn.cursor()

    request_headers_json = json.dumps(full_flow["request"].get("headers", {}))
    response_headers_json = json.dumps(full_flow["response"].get("headers", {}))
    
    values = (
        full_flow["request"].get("ip"),
        full_flow["request"].get("host"),
        full_flow["request"].get("url"),
        full_flow["request"].get("method"),
        full_flow["response"].get("status_code"),
        full_flow["response"].get("reason"),
        full_flow["request"].get("timestamp"),
        full_flow["response"].get("timestamp"),
        full_flow["request"].get("http_version"),
        full_flow["response"].get("http_version"),
        request_headers_json,
        response_headers_json,
        full_flow["request"].get("body", ""),
        full_flow["response"].get("body", "")
    )
    
    c.execute('''
        INSERT INTO logs (
            ip,
            host,
            url,
            method,
            status_code,
            reason,
            request_timestamp,
            response_timestamp,
            request_http_version,
            response_http_version,
            request_headers,
            response_headers,
            request_body,
            response_body
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', values)
    conn.commit()


def cleanup_old_entries(conn, minutes):
    """
    Delete log entries from the database that are older than the specified number of minutes.
    
    Parameters:
        conn (sqlite3.Connection): The SQLite database connection.
        minutes (int): The age threshold in minutes. Entries older than now - minutes will be deleted.
    """
    cutoff = time.time() - minutes * 60  # Compute the cutoff timestamp.
    c = conn.cursor()
    c.execute("DELETE FROM logs WHERE request_timestamp < ?", (cutoff,))
    conn.commit()


token_map: dict[str, AppStoreToken] = {}
conn = setup_db()