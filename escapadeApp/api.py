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

@app.route('/api/writer/submissions', methods=['GET', 'POST'])
@cross_origin('*')
def submissions():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(
        (Write.status == 'Submitted') & (Write.author_id == user.id)).all()
    articles_destination = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(
        (Write.status == 'Submitted') & (Write.author_id == user.id)).all()
    articles_attraction = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).filter(
        (Write.status == 'Submitted') & (Write.author_id == user.id)).all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    for article in articles_destination:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['location'] = destination.location
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    for article in articles_attraction:
        destination = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['location'] = destination.location
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output})

@app.route('/api/writer/drafts', methods=['GET', 'POST'])
@cross_origin('*')
def drafts():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(
        (Write.status == 'Drafted') & (Write.author_id == user.id)).all()
    articles_destination = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(
        (Write.status == 'Drafted') & (Write.author_id == user.id)).all()
    articles_attraction = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).filter(
        (Write.status == 'Drafted') & (Write.author_id == user.id)).all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    for article in articles_destination:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['location'] = destination.location
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    for article in articles_attraction:
        destination = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['location'] = destination.location
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'drafts': output})

@app.route('/api/editor/submissions', methods=['GET', 'POST'])
@cross_origin('*')
def editor_submissions():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(Write.status == 'Submitted').all()
    articles2 = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(Write.status == 'Submitted').all()
    articles3 = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).filter(
        Write.status == 'Submitted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    for article in articles2:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)
    for article in articles3:
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = base64.b64encode(attraction.photo)
        dict['region_id'] = attraction.region_id
        dict['write_id'] = attraction.write_id
        destination = Destination.query.filter_by(destination_id=attraction.destination_id).first()
        if destination is not None:
            dict['destination_id'] = attraction.destination_id
        dict['date'] = article.date
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        dict['status'] = article.status
        output.append(dict)

    return jsonify({'submissions': output})

@app.route('/api/writer/submission/edit', methods=['GET', 'POST'])
@cross_origin('*')
def edit_submissions():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    article = Write.query.filter_by(write_id=data['write_id']).first()
    output = []
    region = Region.query.filter_by(write_id=article.write_id).first()
    dict = {}
    dict['name'] = region.name
    dict['content'] = region.content
    dict['photo'] = base64.b64encode(region.photos)
    dict['region_id'] = region.region_id
    dict['write_id'] = article.write_id
    dict['date'] = article.date
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'submission': output})

@app.route('/api/writer/submission/edit-destination', methods=['GET', 'POST'])
@cross_origin('*')
def edit_submissions_destination():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    article = Write.query.filter_by(write_id=data['write_id']).first()
    output = []
    destination = Destination.query.filter_by(write_id=article.write_id).first()
    region = Region.query.filter_by(region_id=destination.region_id).first()
    dict = {}
    dict['name'] = destination.name
    dict['content'] = destination.content
    dict['photo'] = base64.b64encode(destination.photo)
    dict['region_id'] = destination.region_id
    dict['location'] = destination.location
    dict['write_id'] = article.write_id
    dict['region'] = region.name
    dict['date'] = article.date
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'submission': output})

@app.route('/api/writer/submission/edit-attraction', methods=['GET', 'POST'])
@cross_origin('*')
def edit_submissions_attraction():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    article = Write.query.filter_by(write_id=data['write_id']).first()
    output = []
    attraction = Attraction.query.filter_by(write_id=article.write_id).first()
    dict = {}
    dict['name'] = attraction.name
    dict['content'] = attraction.content
    dict['photo'] = base64.b64encode(attraction.photo)
    dict['region_id'] = attraction.region_id
    if attraction.destination_id is not None:
        destination = Destination.query.filter_by(destination_id = attraction.destination_id).first()
        dict['destination_id'] = attraction.destination_id
        dict['destination'] = destination.name
    region = Region.query.filter_by(region_id=attraction.region_id).first()
    dict['region'] = region.name
    dict['location'] = attraction.location
    dict['write_id'] = article.write_id
    dict['date'] = article.date
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'submission': output})

@app.route('/api/writer/submit/draft', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region.query.filter_by(write_id=get_write.write_id).first()
    region.name=data['name']
    region.content=data['content']
    region.photos=photo.photo
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/draft-destination', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    destination = Destination.query.filter_by(write_id=get_write.write_id).first()
    destination.name=data['name']
    destination.content=data['content']
    destination.photo=photo.photo
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/draft-attraction', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    attraction = Attraction.query.filter_by(write_id=get_write.write_id).first()
    attraction.name=data['name']
    attraction.content=data['content']
    attraction.photo=photo.photo
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(name=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/edit', methods=['GET',  'POST'])
@cross_origin('*')
def edit_submit():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    region = Region.query.filter_by(write_id=get_write.write_id).first()
    region.name=data['name']
    region.content=data['content']
    region.photos=photo.photo
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/edit/destination', methods=['GET',  'POST'])
@cross_origin('*')
def edit_submit_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    destination = Destination.query.filter_by(write_id=get_write.write_id).first()
    destination.name=data['name']
    destination.content=data['content']
    destination.photo=photo.photo
    destination.location=data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/edit/attraction', methods=['GET',  'POST'])
@cross_origin('*')
def edit_submit_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(username=user.username).order_by(Photo.photo_id.desc()).first()
    attraction = Attraction.query.filter_by(write_id=get_write.write_id).first()
    attraction.name=data['name']
    attraction.content=data['content']
    attraction.photo=photo.photo
    attraction.location=data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(name=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/publish/region', methods=['POST'])
@cross_origin('*')
def editor_submit_reg():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    region = Region.query.filter_by(write_id=data['write_id']).first()
    region.name = data['region']
    region.content = data['content']
    db.session.commit()
    write.status = 'Posted'
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/publish/destination', methods=['POST'])
@cross_origin('*')
def editor_submit_des():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    destination = Destination.query.filter_by(write_id=data['write_id']).first()
    destination.name = data['name']
    destination.content = data['content']
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    db.session.commit()
    write.status = 'Posted'
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/publish/attraction', methods=['POST'])
@cross_origin('*')
def editor_submit_att():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
    attraction.name = data['name']
    attraction.content = data['content']
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(name=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    db.session.commit()
    write.status = 'Posted'
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/delete/region', methods=['POST'])
@cross_origin('*')
def editor_delete_reg():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    region = Region.query.filter_by(write_id=data['write_id']).first()
    db.session.delete(region)
    db.session.commit()
    db.session.delete(write)
    db.session.commit()
    return jsonify({'message': 'Deleted successfully!'})

@app.route('/api/editor/delete/destination', methods=['POST'])
@cross_origin('*')
def editor_delete_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    destination = Destination.query.filter_by(write_id=data['write_id']).first()
    db.session.delete(destination)
    db.session.commit()
    db.session.delete(write)
    db.session.commit()
    return jsonify({'message': 'Deleted successfully!'})

@app.route('/api/editor/delete/attraction', methods=['POST'])
@cross_origin('*')
def editor_delete_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
    db.session.delete(attraction)
    db.session.commit()
    db.session.delete(write)
    db.session.commit()
    return jsonify({'message': 'Deleted successfully!'})

@app.route('/api/editor/edit/region', methods=['POST'])
@cross_origin('*')
def editor_edit_reg():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    region = Region.query.filter_by(write_id=data['write_id']).first()
    region.name = data['region']
    region.content = data['content']
    db.session.commit()
    write.status = 'Checked'
    write.comment = data['comment']
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/edit/destination', methods=['POST'])
@cross_origin('*')
def editor_edit_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    destination = Destination.query.filter_by(write_id=data['write_id']).first()
    destination.name = data['name']
    destination.content = data['content']
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    db.session.commit()
    write.status = 'Checked'
    write.comment = data['comment']
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/edit/attraction', methods=['POST'])
@cross_origin('*')
def editor_edit_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
    attraction.name = data['name']
    attraction.content = data['content']
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(name=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    db.session.commit()
    write.status = 'Checked'
    write.comment = data['comment']
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/get_regions')
@cross_origin('*')
def regions():
    articles = Write.query.filter_by(status='Posted').all()
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        output.append(dict)
    return jsonify({'regions': output})

@app.route('/get_destinations')
@cross_origin('*')
def get_destinations():
    articles = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['region_id'] = destination.region_id
        region = Region.query.filter_by(region_id=destination.region_id).first()
        dict['region_name'] = region.name
        output.append(dict)
    return jsonify({'destinations': output})

@app.route('/get_posted')
@cross_origin('*')
def get_posted():
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(Write.status == 'Posted').all()
    articles2 = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(Write.status == 'Posted').all()
    articles3 = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    for article in articles2:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['location'] = destination.location
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        region = Region.query.filter_by(region_id=destination.region_id).first()
        dict['region_name'] = region.name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    for article in articles3:
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = base64.b64encode(attraction.photo)
        dict['region_id'] = attraction.region_id
        dict['write_id'] = attraction.write_id
        destination = Destination.query.filter_by(destination_id=attraction.destination_id).first()
        if destination is not None:
            dict['destination_id'] = attraction.destination_id
        region = Region.query.filter_by(region_id=attraction.region_id).first()
        dict['region_name'] = region.name
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)

    return jsonify({'submissions': output})

@app.route('/get/all/attractions')
@cross_origin('*')
def get_all_attractions():
    articles3 = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles3:
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = base64.b64encode(attraction.photo)
        dict['region_id'] = attraction.region_id
        dict['write_id'] = attraction.write_id
        destination = Destination.query.filter_by(destination_id=attraction.destination_id).first()
        if destination is not None:
            dict['destination_id'] = attraction.destination_id
        region = Region.query.filter_by(region_id=attraction.region_id).first()
        dict['region_name'] = region.name
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'posts': output})

@app.route('/get/all/destinations')
@cross_origin('*')
def get_all_destinations():
    articles2 = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles2:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        region = Region.query.filter_by(region_id=destination.region_id).first()
        dict['region_name'] = region.name
        dict['location'] = destination.location
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'posts': output})

@app.route('/get/all/region')
@cross_origin('*')
def get_all_region():
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(Write.status == 'Posted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'posts': output})

@app.route('/get/region')
@cross_origin('*')
def get_region():
    data = request.get_json()
    output = []
    dict = {}
    region = Region.query.filter_by(name=data['title']).first()
    article = Write.query.filter_by(write_id=region.write_id).first()
    dict['type'] = 'Region'
    dict['name'] = region.name
    dict['content'] = region.content
    dict['photo'] = base64.b64encode(region.photos)
    dict['region_id'] = region.region_id
    dict['write_id'] = article.write_id
    dict['date'] = article.date.strftime('%B %d, %Y')
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    user = User.query.filter_by(username=article.author_name).first()
    dict['author'] = user.firstname + ' ' + user.lastname
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'post': output})

@app.route('/get/destination')
@cross_origin('*')
def get_destination():
    data = request.get_json()
    output = []
    dict = {}
    destination = Destination.query.filter_by(name=data['title']).first()
    article = Write.query.filter_by(write_id=destination.write_id).first()
    dict['type'] = 'Destination'
    dict['name'] = destination.name
    dict['content'] = destination.content
    dict['photo'] = base64.b64encode(destination.photo)
    dict['region_id'] = destination.region_id
    region = Region.query.filter_by(region_id=destination.region_id).first()
    dict['region_name'] = region.name
    dict['write_id'] = article.write_id
    dict['location'] = destination.location
    dict['date'] = article.date.strftime('%B %d, %Y')
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    user = User.query.filter_by(username=article.author_name).first()
    dict['author'] = user.firstname + ' ' + user.lastname
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'post': output})

@app.route('/get/attraction')
@cross_origin('*')
def get_attraction():
    data = request.get_json()
    output = []
    dict = {}
    attraction = Attraction.query.filter_by(name=data['title']).first()
    article = Write.query.filter_by(write_id=attraction.write_id).first()
    dict['type'] = 'Attraction'
    dict['name'] = attraction.name
    dict['content'] = attraction.content
    dict['photo'] = base64.b64encode(attraction.photo)
    dict['region_id'] = attraction.region_id
    dict['write_id'] = article.write_id
    region = Region.query.filter_by(region_id=attraction.region_id).first()
    dict['region_name'] = region.name
    dict['date'] = article.date.strftime('%B %d, %Y')
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    user = User.query.filter_by(username=article.author_name).first()
    dict['author'] = user.firstname + ' ' + user.lastname
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'post': output})

@app.route('/get/all/user')
@cross_origin('*')
def get_all_users():
    output = []  
    users = User.query.filter((User.role_id == str(2)) | (User.role_id == str(3))).all()
    for user in users:
        dict = {}
        dict['id'] = user.id
        dict['public_id'] = user.public_id
        dict['username'] = user.username
        dict['firstname'] = user.firstname
        dict['middlename'] = user.middlename
        dict['fullname'] = user.firstname+ ' ' + user.middlename + ' ' + user.lastname
        dict['age'] = user.age
        dict['contact'] = user.contact
        dict['address'] = user.address
        dict['role_id'] = user.role_id
        output.append(dict)
    return jsonify({'status': 'ok', 'entries': output, 'count': len(output)})

@app.route('/api/promotedemote', methods=['POST'])
@cross_origin('*')
def promote_and_demote():
    data = request.get_json()
    user = User.query.filter_by(id = data['userid']).first()

    if data['response'] == 'yes':
        user.role_id = 2
        db.session.commit()

    else:
        user.role_id = 3
        db.session.commit()

    return jsonify({'message': 'Registered successfully!'})

@app.route('/api/profile', methods=['GET'])
@cross_origin('*')
def profile():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    dict = {}
    output = []
    dict['firstname'] = user.firstname
    dict['middlename'] = user.middlename
    dict['lastname'] = user.lastname
    dict['age'] = user.age
    dict['contact'] = user.contact
    dict['birthday'] = user.birthday
    output.append(dict)

    print('Good')
    return jsonify({'infos': output})


@app.route('/get_yourpost')
@cross_origin('*')
def your_post():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    authorid = user.id
    print authorid
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter((Write.status == 'Posted') & (Write.author_id == authorid)).all()
    articles2 = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter((Write.status == 'Posted') & (Write.author_id == authorid)).all()
    articles3 = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id and Write.author_id == authorid).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = base64.b64encode(region.photos)
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    for article in articles2:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = base64.b64encode(destination.photo)
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    for article in articles3:
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = base64.b64encode(attraction.photo)
        dict['region_id'] = attraction.region_id
        dict['write_id'] = attraction.write_id
        destination = Destination.query.filter_by(destination_id=attraction.destination_id).first()
        if destination is not None:
            dict['destination_id'] = attraction.destination_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)

    return jsonify({'submissions': output})

