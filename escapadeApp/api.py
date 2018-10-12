from escapadeApp import *
from models import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify ({'message':'token is missing!'}), 401

        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])

            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password_hash=hashed_password, firstname=data['firstname'], middlename=data['middlename'],
                    lastname=data['lastname'], contact=data['contact'], address=data['address'], birthday=data['birthday'], role_id=2, status=False,
                    age=data['age'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'Registered successfully!'})

@app.route('/api/login/', methods=['GET'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm = "Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=90)}, app.config['SECRET_KEY'])

        print 'Token generated!'
        return jsonify({'status':'ok', 'token': token.decode('UTF-8'), 'role_id':user.role_id, 'public_id':user.public_id,'message':'login successful!'})

