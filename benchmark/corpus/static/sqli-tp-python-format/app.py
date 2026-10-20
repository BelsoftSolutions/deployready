def get_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))
    return cursor.fetchone()
