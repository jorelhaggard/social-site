from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import sshtunnel
from socket import gethostname
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, joinedload
import logging
import pytz
from m4o_tinkerin import resolve_ip, connect_to_mongo


resolve_ip()
connect_to_mongo()
############################################# CONFIGURATION #########################################################
tz = pytz.timezone('utc')
logging.basicConfig(filename='/home/jorelb/mysite/error.log', level=logging.ERROR)



app = Flask(__name__)
app.secret_key = 'hihihihihihi'  # Set a secret key for session management
app.debug=True
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

sshtunnel.SSH_TIMEOUT = 50.0
sshtunnel.TUNNEL_TIMEOUT = 50.0

postgres_hostname = "jorelb-3462.postgres.pythonanywhere-services.com"
postgres_host_port = 13462

BASE_MEDIA_FOLDER = 'static'
UPLOAD_FOLDER = os.path.join('/home/jorelb/mysite', BASE_MEDIA_FOLDER)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

////////////////////////////////////////////

# Configure SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://super:butcrax!!@jorelb-3462.postgres.pythonanywhere-services.com:13462/m4o'
db = SQLAlchemy(app)

////////////////////////////////////////////

@app.template_filter('time_since')
def timesince_filter(dt):
    now = datetime.now(tz)

    if dt.tzinfo is None:
        dt = tz.localize(dt)
    diff = now - dt
    if diff < timedelta(minutes=1):
        return "Now"
    elif diff < timedelta(hours=1):
        mins = diff.seconds // 60
        return f"{mins} minute{'s' if mins > 1 else ''} ago"
    elif diff < timedelta(days=1):
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    else:
        days = diff.days
        return f"{days} day{'s' if days > 1 else ''} ago"




class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, ForeignKey('post.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False, index=True)
    comment_content = db.Column(db.String(500), nullable=False)
    parent_id = db.Column(db.Integer, index=True, nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    users = relationship("User", back_populates="comments")
    posts = relationship('Post', back_populates='comments')


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, ForeignKey('post.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False, index=True)
    liked = db.Column(db.Boolean, default=True)
    users = relationship("User", back_populates="likes")
    posts = relationship('Post', back_populates='likes')



class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caption = db.Column(db.String(500))
    media = db.Column(db.String(500))  # Path to the image/video file
    media_type = db.Column(db.String(20))  # Either 'image' or 'video'
    user_id = db.Column(db.Integer, ForeignKey('user.id'))  # Assuming 'user' is the table name for User model
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)

    users = relationship('User', back_populates='posts')
    comments = relationship('Comment', back_populates='posts')
    likes = relationship('Like', back_populates='posts')



@app.route('/', methods=['POST', 'GET'])
def main():
    if session.get('logged_in'):
        return render_template('index.html')
    return redirect(url_for('login'))


def save_profile_picture(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(f'IMG{current_user.id}.{file.filename.rsplit(".", 1)[1].lower()}')
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profilepictures', filename)
        file.save(save_path)
        return os.path.join('static', 'profilepictures', filename)
    return None

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    bio = request.form.get('bio')
    file = request.files.get('profile_picture')
    if file.filename == '':
        file = url_for('static') + '/profilepictures/default.png'
    # Update bio
    current_user.bio = bio or None

    # profile picture upload
    if file:
        saved_path = save_profile_picture(file)
        if saved_path:
            current_user.profile_picture = saved_path

    db.session.commit()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('myaccount'))




@app.route('/get-comments/<int:post_id>', methods=['GET'])
def get_comments(post_id):
    app.logger.info(f"Accessing get_comments for post_id: {post_id}")
    post = Post.query.options(joinedload('comments')).filter_by(id=post_id).first()
    if not post:
        return jsonify(success=False, message="Post not found"), 404

    comments = post.comments
    serialized_comments = [{
        'user_id': comment.user_id,
        'username': comment.users.username,
        'content': comment.comment_content,
        'timestamp': comment.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'time_since': timesince_filter(comment.timestamp)
    } for comment in comments]

    return jsonify(success=True, comments=serialized_comments)



@app.route('/report-error', methods=['POST'])
def report_error():
    data = request.json
    error_message = data.get('error', '')
    app.logger.error(f'JavaScript reported error: {error_message}')
    return jsonify(success=True)




@app.route('/profile/<int:user_id>', methods=['POST', 'GET'])
def profile(user_id):
    # Fetch the user
    userid = user_id

    # If user doesn't exist return 404 error
    if not userid:
        abort(404)
    if current_user.is_authenticated and user_id == current_user.id:
        return redirect(url_for('myaccount'))
    # fetch the posts of the user
    posts = Post.query.filter_by(user_id=user_id).options(joinedload('comments'), joinedload('likes')).all()
    user = User.query.get(user_id)
    # Sort comments for each post
    for post in posts:
        post.comments = sorted(post.comments, key=lambda c: c.timestamp, reverse=False)

    return render_template('profile.html', posts=posts, user=user)




@app.route('/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    try:
        # Check if the user is authenticated
        if not current_user.is_authenticated:
            abort(401)  # Unauthorized

        # Fetch the post
        post = Post.query.get(post_id)
        if not post:
            return jsonify(success=False, message="Post not found"), 404

        # Check if an interaction already exists
        like = Like.query.filter_by(post_id=post_id, user_id=current_user.id).first()

        # If interaction exists and it's already liked, delete the "like"
        if like and like.liked:
            db.session.delete(like)
            db.session.commit()
            return jsonify(success=True, action="unliked", newState=False)

        # If interaction exists but not liked, "like"
        elif like and not like.liked:
            like.liked = True
            db.session.commit()
            return jsonify(success=True, action="liked", newState=True)

        # If interaction doesn't exist, create one and "like"
        else:
            new_like = Like(post_id=post_id, user_id=current_user.id, liked=True)
            db.session.add(new_like)
            db.session.commit()
            return jsonify(success=True, action="liked", newState=True)

    except Exception as e:
        # Rollback in case there is any error
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500



@app.route('/post-comment/<int:post_id>', methods=['POST'])
def post_comment(post_id):
    # Check if the user is authenticated
    if not current_user.is_authenticated:
        return jsonify(success=False, message="Unauthorized"), 401

    # Fetch the post to ensure it exists
    post = Post.query.get(post_id)
    if not post:
        return jsonify(success=False, message="Post not found"), 404

    # Get the comment from the request
    data = request.json
    comment_content = data.get('comment')

    # Validate the comment content
    if not comment_content or len(comment_content) > 500:
        return jsonify(success=False, message="Invalid comment"), 400


    comment = Comment(post_id=post_id, user_id=current_user.id, comment_content=comment_content, parent_id=None, timestamp=datetime.utcnow())
    db.session.add(comment)

    try:
        db.session.commit()
        return jsonify(success=True,
                       message="Comment posted successfully",
                       comment_content=comment.comment_content,
                       username=current_user.username,
                       timestamp=str(timesince_filter(comment.timestamp)))
    except Exception as e:
        logging.error("Error occurred while posting the comment: " + str(e))
        return jsonify(success=False, message="An error occurred while posting the comment"), 500



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('main'))
        else:
            flash('Login failed. Please try again.', 'error')

    return render_template('login.html')



class Follow(db.Model):
    __tablename__ = 'follows'

    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # timestamp for when the follow was created
    def __repr__(self):
        return f'<Follow {self.follower_id} -> {self.following_id}>'


# Define database model for user data
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(60), nullable=False)
    name = db.Column(db.String(60), nullable=False)
    marketing = db.Column(db.String(5), nullable=False)
    profilepicture = db.Column(db.String(255))
    bio = db.Column(db.String(500))
    posts = relationship('Post', back_populates='users', lazy='dynamic')
    comments = relationship('Comment', back_populates='users')
    likes = relationship('Like', back_populates='users')
    followers = db.relationship(
        'User', secondary='follows',
        primaryjoin=(id == Follow.follower_id),
        secondaryjoin=(id == Follow.following_id),
        backref=db.backref('following', lazy='dynamic'),
        lazy='dynamic'
    )
    def __repr__(self):
        return f'<User {self.username}>'




@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get user input from form
        username = request.form.get('field-2')
        password = request.form.get('field')
        email = request.form.get('email')
        name = request.form.get('name')
        marketing = request.form.get('I-consent-to-receive-marketing-emails-from-M4O')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Please choose another."

        # Create a new user record
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, email=email, name=name, marketing=marketing)

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login page after signup
        return redirect(url_for('login'))

    # Render the signup form
    return render_template('signup.html')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_media(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        ext = filename.rsplit('.', 1)[1].lower()
        subfolder = 'postvideos' if ext in ['mp4', 'mov'] else 'postimages'

        save_path = os.path.join(app.config['UPLOAD_FOLDER'], subfolder, filename)
        relative_path =  subfolder + '/' + filename

        file.save(save_path)
        return relative_path

    return None



@app.route('/createpost', methods=['GET', 'POST'])
@login_required
def createpost():
    if request.method == 'POST':
        caption = request.form.get('Caption')

        # Handle media upload, save it, and get the path
        image_file = request.files.get('image')
        video_file = request.files.get('video')

        if image_file and image_file.filename.startswith("static/"):
            image_file.filename = image_file.filename.replace("static/", "", 1)

        if video_file and video_file.filename.startswith("static/"):
            video_file.filename = video_file.filename.replace("static/", "", 1)

        # Determine which media type is provided and save it
        media_file = image_file if image_file and allowed_file(image_file.filename) else video_file
        saved_path = save_media(media_file) if media_file and allowed_file(media_file.filename) else None

        if saved_path:
            ext = saved_path.rsplit('.', 1)[1].lower()
            media_type = 'video' if ext in ['mp4', 'mov'] else 'image'

            post = Post(caption=caption, media=saved_path, media_type=media_type, user_id=current_user.id)
            db.session.add(post)
            db.session.commit()

            # Redirect to feed or some other page
            return redirect(url_for('myfeed'))

    return render_template('createpost.html')



@app.route('/myfeed', methods=['GET', 'POST'])
def myfeed():
    posts = Post.query.options(joinedload('comments'), joinedload('likes')).all()

    for post in posts:
        post.comments = sorted(post.comments, key=lambda c: c.timestamp, reverse=False)

    return render_template('miffed.html', posts=posts)



@app.route('/myaccount', methods=['GET'])
@login_required
def myaccount():
    # Retrieve all posts of the currently logged-in user.
    posts = Post.query.filter_by(user_id=current_user.id).options(joinedload('comments'), joinedload('likes')).all()
    posts_count = len(posts)
    # Sort the comments for each post by timestamp.
    for post in posts:
        post.comments = sorted(post.comments, key=lambda c: c.timestamp, reverse=False)

    user = User.query.filter_by(id=current_user.id)
    return render_template('myaccount.html', posts=posts, user=user, posts_count=posts_count)


@app.route('/mymessages', methods=['GET'])
def mymessages():
    return(render_template('mymessages.html'))


@app.route('/newmessage', methods=['GET'])
def newmessage():
    return(render_template('new-message.html'))


@app.route('/newmessagesubmit', methods=['POST'])
def newmessagesubmit():
    return(redirect(url_for('mymessages') + '#messagus'))


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    if 'liveconsole' not in gethostname():
        app.run()

