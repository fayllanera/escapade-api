from escapadeApp import *
from models import *
from flask_cors import cross_origin
import binascii, base64

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
                    lastname=data['lastname'], contact=data['contact'], address=data['address'], birthday=data['birthday'], role_id=2,
                    age=data['age'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'Registered successfully!'})

@app.route('/api/login/', methods=['GET'])
def login():
    auth = request.authorization
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        hashed_password = generate_password_hash('password', method='sha256')
        add_admin = User(public_id=str(uuid.uuid4()), username='admin', password_hash=hashed_password,
                        firstname='admin', middlename='admin',
                        lastname='admin', contact='09955890556', address='admin',
                        birthday='1998-08-27', role_id=1,
                        age=99)
        db.session.add(add_admin)
        db.session.commit()

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm = "Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=90)},
            app.config['SECRET_KEY'])
        print 'Token generated!'
        return jsonify({'status':'ok', 'token': token.decode('UTF-8'), 'role_id':user.role_id, 'public_id':user.public_id,'message':'login successful!'})

@app.route('/api/writer/submit', methods=['POST'])
@cross_origin('*')
def writer_submit():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Submitted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region(name=data['name'], content=data['content'],
                    photos=photo.photo,
                    write_id=get_write.write_id)
    db.session.add(region)
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/destination', methods=['POST'])
@cross_origin('*')
def writer_submit_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Submitted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region.query.filter_by(name=data['region']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        destination = Destination(name=data['name'], content=data['content'],
                        photo=photo.photo, location=data['location'],
                        region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(destination)
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/attraction', methods=['POST'])
@cross_origin('*')
def writer_submit_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Submitted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region.query.filter_by(name=data['region']).first()
    destination = Destination.query.filter_by(name=data['destination']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    elif destination is None:
        return jsonify({'error': 'failed to add'})
    else:
        attraction = Attraction(name=data['name'], content=data['content'],
                        photo=photo.photo, location=data['location'], destination_id=destination.destination_id,
                        region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(attraction)
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft/destination', methods=['POST'])
@cross_origin('*')
def writer_draft_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Drafted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region.query.filter_by(name=data['region']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        destination = Destination(name=data['name'], content=data['content'],
                        photo=photo.photo, location=data['location'],
                        region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(destination)
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft/attraction', methods=['POST'])
@cross_origin('*')
def writer_draft_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Drafted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region.query.filter_by(name=data['region']).first()
    destination = Destination.query.filter_by(name=data['destination']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    elif destination is None:
        return jsonify({'error': 'failed to add'})
    else:
        attraction = Attraction(name=data['name'], content=data['content'],
                        photo=photo.photo, location=data['location'], destination_id=destination.destination_id,
                        region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(attraction)
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft', methods=['POST'])
@cross_origin('*')
def writer_draft():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Drafted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region(name=data['name'], content=data['content'],
                    photos=photo.photo,
                    write_id=get_write.write_id)
    db.session.add(region)
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/upload', methods=['POST'])
@cross_origin('*')
def upload_photo():
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    file = binascii.a2b_base64(data['filename'])
    photo = Photo(username=data['username'], photo=file)
    db.session.add(photo)
    db.session.commit()
    return jsonify({'success': 'true'})

@app.route('/api/writer/delete', methods=['POST'])
@cross_origin('*')
def delete():
    data = request.get_json()
    print(data)
    file = binascii.a2b_base64(data['filename'])
    photo = Photo.query.filter((Photo.username == data['username']) & (Photo.photo == file)).first()
    db.session.delete(photo)
    db.session.commit()
    return jsonify({'success': 'true'})

