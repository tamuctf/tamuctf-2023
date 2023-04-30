from flask import *
import mysql.connector

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/api/chpass', methods=['POST'])
def change_password():
    username = request.form.get('username')
    
    db = mysql.connector.connect(host="db", user="ro_user", password="c207876a6365f76aa03ecff9746af6f6", database="users")
    cursor = db.cursor()

    query = "SELECT username FROM users.users WHERE username = '" + username + "' LIMIT 1;"

    cursor.execute(query)

    for ret_user in cursor:
        cursor.close()
        db.close()
        return jsonify({'res': 'exists'})

    return jsonify({'res': 'not exists'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

