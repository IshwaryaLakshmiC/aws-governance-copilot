import psycopg2
import psycopg2.extras
from app.core.config import get_settings

settings = get_settings()


def get_connection():
    return psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
        sslmode="require",
        cursor_factory=psycopg2.extras.RealDictCursor
    )


def execute(sql: str, params=None, fetch=False):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if fetch:
                result = cur.fetchall()
                conn.commit()
                return [dict(r) for r in result]
            conn.commit()
    finally:
        conn.close()


def executemany(sql: str, params_list: list):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.executemany(sql, params_list)
            conn.commit()
    finally:
        conn.close()
