def get_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()
