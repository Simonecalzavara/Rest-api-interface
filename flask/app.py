from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_socketio import SocketIO, send
import socket

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # Connessione al database sqlite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret' # Chiave segreta per generare i token
app.config['SECRET_KEY'] = 'secret' # Chiave segreta per SocketIO
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app)

BROKER_IP = '127.0.0.1'
BROKER_PORT = 40008

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    


def connect_to_broker():
    # Creazione del socket TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connessione al broker
        s.connect((BROKER_IP, BROKER_PORT))
        s.sendall(message.encode('utf-8'))

        
def send_message_to_broker(message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    
        # Invio del messaggio al broker
        s.sendall(message.encode('utf-8'))

@app.route('/')
def hello():
    return 'Hello, Home!\n'

@socketio.on('message')
def handle_message(message):
    send_message_to_broker(message)
    send('Message published to broker', broadcast=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'})
    else:
        return render_template('register.html')
    
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        if 'username' in request.form and 'password' in request.form:
            username = request.form['username']
            password = request.form['password']
            
            user = User.query.filter_by(username=username).first()
            if not user:
                return render_template('login.html', error='Invalid username or password')

            if user.password == password:
                access_token = create_access_token(identity=user.id)
                send_message_to_broker('[CONNECT]')
                return redirect(url_for('forum'))
            else:
                return render_template('login.html', error='Invalid username or password')
        else:
            return render_template('login.html', error='Username and password are required')
    else:
        return render_template('login.html')
        
@app.route('/forum', methods=['GET','POST'])
def forum():
    if request.method == 'POST':
    
    	topic = request.form['topic']
    	send_message_to_broker('[SUBSCRIBE] {"topic":"%s","message":"%s"}' % ("topic", "message"))
    	message = request.form['message']
    	
    	send_message_to_broker('[SEND] {"topic":"%s","message":"%s"}' % ("topic", "message"))
    
    	return render_template('forum.html')
     
    else:
     
     	return render_template('forum.html')

@app.route('/message', methods=['GET','POST'])
def message():
    if request.method == 'POST':
    
    
    	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connessione al broker
       	    s.connect((BROKER_IP, BROKER_PORT))
       	    
       	    #connection = '[CONNECT]\n'
       	    
       	    #s.sendall(connection.encode("UTF-8"))
       	    #s.recv(1024)
       	    
       	    message_prova = '[SUBSCRIBE]{"topic":"casa"}\n'
       	    print(message_prova.encode())
       	    s.sendall(message_prova.encode())
       	    #s.recv(1024)
       	    #topic = request.form['topic']
       	    #message = request.form['message']
       	    #send_message_to_broker('[SEND] {"topic":"%s","message":"%s"}' % ("topic", "message")
            return render_template('message.html')
    
    else: 
    	
        return render_template('message.html')
    
    
@app.route('/publish', methods=['GET','POST'])
def publish():
    message = request.form['message']
    send_message_to_broker('[CONNECT]')
    return jsonify({'message': 'Message published successfully'})

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({'message': 'This is a protected endpoint'})

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)