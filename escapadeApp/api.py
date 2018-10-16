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

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm = "Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=90)}, app.config['SECRET_KEY'])

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
    articles = Write.query.filter((Write.author_id == user.id) & (Write.status == 'Submitted')).all()
    output = []
    for article in articles:
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

    return jsonify({'submissions': output})

@app.route('/api/editor/submissions', methods=['GET', 'POST'])
@cross_origin('*')
def editor_submissions():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    articles = Write.query.filter_by(status='Submitted').all()
    output = []
    for article in articles:
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