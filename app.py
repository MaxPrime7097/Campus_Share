from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus_share.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modèle Fichier
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Modèle HelpRequest
class HelpRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Modèle Post (fil d'actualité)
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='posts')

# Modèle Message (messagerie)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

# Table d'association pour les amis
friends = db.Table('friends',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'))
)

# Modèle Utilisateur (fusionné avec gestion des amis)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    filiere = db.Column(db.String(80), nullable=False)
    niveau = db.Column(db.String(80), nullable=False)
    friends = db.relationship(
        'User',
        secondary=friends,
        primaryjoin=(friends.c.user_id == id),
        secondaryjoin=(friends.c.friend_id == id),
        backref=db.backref('friend_of', lazy='dynamic'),
        lazy='dynamic'
    )

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def add_friend(self, user):
        if not self.is_friend(user):
            self.friends.append(user)

    def remove_friend(self, user):
        if self.is_friend(user):
            self.friends.remove(user)

    def is_friend(self, user):
            return self.friends.filter(friends.c.friend_id == user.id).count() > 0
    
    @property
    def files(self):
            return File.query.filter_by(user_id=self.id).all()
    
    @property
    def help_requests(self):
            return HelpRequest.query.filter_by(user_id=self.id).all()
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

# Page d'accueil
@app.route('/')
def index():
    return redirect(url_for('dashboard'))
# Connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Connexion réussie !', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
    return render_template('login.html')

# Inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        filiere = request.form['filiere']
        niveau = request.form['niveau']
        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur existe déjà.', 'error')
        else:
            user = User(username=username, filiere=filiere, niveau=niveau)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# Déconnexion
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté.', 'success')
    return redirect(url_for('index'))

# Page de profil
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user  # Utilise Flask-Login pour obtenir l'utilisateur courant
    return render_template('profile.html', user=user)

# Upload de fichiers
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'jpg', 'png', 'txt', 'pptx', 'xlsx', 'zip', 'rar', 'mp4', 'mp3', 'avi', 'mkv', 'exe', 'iso', 'apk', 'docx', '7z', 'tar', 'csv', 'json', 'xml', 'html', 'css', 'js', 'php', 'java', 'c', 'cpp', 'py'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            flash('Fichier uploadé avec succès !', 'success')
            return redirect(url_for('files'))
        else:
            flash('Type de fichier non autorisé.', 'error')
    return render_template('upload.html')

# Liste des fichiers
@app.route('/files')
@login_required
def files():
    page = request.args.get('page', 1, type=int)
    pagination = File.query.filter_by(user_id=current_user.id).paginate(page=page, per_page=10)
    files = pagination.items
    return render_template('files.html', files=files, pagination=pagination)

# Télécharger un fichier
@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Page d'aide
@app.route('/help', methods=['GET', 'POST'])
@login_required
def help():
    if request.method == 'POST':
        subject = request.form['subject']
        message = request.form['message']
        help_request = HelpRequest(subject=subject, message=message, user_id=current_user.id)
        db.session.add(help_request)
        db.session.commit()
        flash('Demande d\'aide envoyée avec succès !', 'success')
        return redirect(url_for('index'))
    return render_template('help.html')

# Page des anciennes épreuves
@app.route('/exams')
@login_required
def exams():
    return render_template('exams.html')

# Fil d'actualités
@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():
    if request.method == 'POST':
        content = request.form['content']
        if content.strip():
            post = Post(content=content, user_id=current_user.id)
            db.session.add(post)
            db.session.commit()
            flash('Publication ajoutée !', 'success')
            return redirect(url_for('feed'))
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('feed.html', posts=posts)
# Tableau de bord
# ...existing code...
@app.route('/dashboard')
@login_required
def dashboard():
    posts = Post.query.order_by(Post.timestamp.desc()).limit(5).all()
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).limit(5).all()
    files = File.query.filter_by(user_id=current_user.id).order_by(File.id.desc()).limit(5).all()
    # Suggestions d'amis (exclure l'utilisateur courant)
    suggestions = User.query.filter(User.id != current_user.id).limit(5).all()
    return render_template('dashboard.html', posts=posts, messages=messages, files=files, user=current_user, suggestions=suggestions)

# Messagerie
@app.route('/messages/<username>', methods=['GET', 'POST'])
@login_required
def messages(username):
    user = User.query.filter_by(username=username).first_or_404()
    # Liste des amis pour la colonne de gauche
    friends = current_user.friends.all()
    # On ne peut écrire qu'à ses amis
    if user == current_user or not current_user.is_friend(user):
        flash("Vous ne pouvez échanger des messages qu'avec vos amis.", "warning")
    if request.method == 'POST':
        content = request.form['content']
        if content.strip():
            msg = Message(content=content, sender_id=current_user.id, receiver_id=user.id)
            db.session.add(msg)
            db.session.commit()
            flash('Message envoyé !', 'success')
            return redirect(url_for('messages', username=username))
    msgs = Message.query.filter(
        or_(
            (Message.sender_id==current_user.id) & (Message.receiver_id==user.id),
            (Message.sender_id==user.id) & (Message.receiver_id==current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()
    return render_template('messages.html', user=user, messages=msgs, friends=friends)
#Gestion des amis
@app.route('/add_friend/<int:user_id>')
@login_required
def add_friend(user_id):
    friend = User.query.get_or_404(user_id)
    if friend != current_user and not current_user.is_friend(friend):
        current_user.add_friend(friend)
        db.session.commit()
        flash(f"{friend.username} a été ajouté à vos amis.", "success")
    return redirect(url_for('profile_username', username=friend.username))

@app.route('/remove_friend/<int:user_id>')
@login_required
def remove_friend(user_id):
    friend = User.query.get_or_404(user_id)
    if current_user.is_friend(friend):
        current_user.remove_friend(friend)
        db.session.commit()
        flash(f"{friend.username} a été retiré de vos amis.", "info")
    return redirect(url_for('profile_username', username=friend.username))
# Liste des utilisateurs
@app.route('/profile/<username>')
@login_required
def profile_username(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)