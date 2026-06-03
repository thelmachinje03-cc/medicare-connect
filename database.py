import os
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/medicare_db")

def get_db_connection():
    """Establish a connection to the PostgreSQL database using DictCursor."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
    return conn

def execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """
    Executes a database query securely using parameterized arguments.
    
    Args:
        query (str): The SQL statement to run.
        params (tuple/dict): Parameterized values for the query.
        fetch_one (bool): Whether to return a single row.
        fetch_all (bool): Whether to return all matching rows.
        commit (bool): Whether to commit transactions (INSERT/UPDATE/DELETE).
        
    Returns:
        The fetched row(s) or the cursor object depending on parameters.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(query, params)
            
            result = None
            if fetch_one:
                result = cur.fetchone()
            elif fetch_all:
                result = cur.fetchall()
                
            if commit:
                conn.commit()
                
            return result
    except Exception as e:
        if conn and commit:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_db():
    """Reads schema.sql and initializes the database tables."""
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    if not os.path.exists(schema_path):
        print(f"Error: {schema_path} does not exist.")
        return

    with open(schema_path, 'r') as f:
        schema_sql = f.read()

    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn.cursor() as cur:
            cur.execute(schema_sql)
        conn.commit()
        print("Database tables initialized successfully.")
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Failed to initialize database: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    init_db()
