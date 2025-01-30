from flask import Flask, render_template, request,redirect,url_for,session,flash
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from functools import wraps
forum_posts=[]
app = Flask(__name__)
app.config['SQLALCHEMY_BINDS'] = {
    'user': 'postgresql://postgres:1505tavi@localhost:5432/User_Management_service',
    'forum': 'postgresql://postgres:1505tavi@localhost:5432/forum_service_db'
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'blabla'
 # Should return success

# Initialize SQLAlchemy and Bcrypt
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# User model for user_management_service

@app.route('/notify_login')
def notify_login():
    # Notify the user they need to log in
    flash('You need to log in first to create a post.')
    next_page = request.args.get('next')  # Get the page the user was attempting to access
    return redirect(url_for('login', next=next_page))
class User(db.Model):
    __bind_key__ = 'user'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="general")  # User roles: general, admin, academic, journalist
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class UserPrototype:
    def __init__(self, role):
        self.role = role

    def clone(self):
        return UserPrototype(self.role)

# Prototypes for each role
general_user = UserPrototype("general")
academic_user = UserPrototype("academic")
journalist_user = UserPrototype("journalist")

class RoleRequest(db.Model):
    __bind_key__ = 'user'  # Bind to the users database
    __tablename__ = 'role_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Requested role (e.g., 'academic', 'journalist')
    phone = db.Column(db.String(20), nullable=False)  # User's phone number
    reason = db.Column(db.Text, nullable=False)  # Reason for requesting the role change
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', or 'rejected'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for the request

    # Relationship with the User model
    user = db.relationship('User', backref='role_requests')

def initialize_role_requests_table():
    with app.app_context():
        role_engine = db.get_engine(app, bind='user')  # Get the user database engine
        db.metadata.create_all(role_engine, tables=[RoleRequest.__table__])  # Create the table

# Call this function to create the table
initialize_role_requests_table()


class Post(db.Model):
    __bind_key__ = 'forum'
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    claim = db.Column(db.String(1000), nullable=False)
    content = db.Column(db.Text, nullable=False)
    claimant = db.Column(db.String(255), nullable=False, default="Unknown")
    publisher = db.Column(db.String(255), nullable=False, default="Unknown")
    rating = db.Column(db.String(500), nullable=False, default="No rating")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=False)

    def get_user(self):
        # Fetch the user who created the post
        user = User.query.filter_by(id=self.user_id).first()
        return user.username if user else "Unknown User"
    def get_role(self):
        user = User.query.filter_by(id=self.user_id).first()
        return user.role if user else "Unknown Role"


class Comment(db.Model):
    __bind_key__ = 'forum'
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # Treat user_id as an integer, not a foreign key

    def get_user(self):
        # Query the user from the User_Management_service database
        user = User.query.filter_by(id=self.user_id).first()
        return user.username if user else "Unknown User"
    def get_role(self):
        user = User.query.filter_by(id=self.user_id).first()
        return user.role if user else "Unknown Role"


# Routes

@app.route('/')
def home():
    return render_template('index.html')  # Render the main page

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate form input
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
            flash("Email or Username already exists!", "danger")
            return redirect(url_for('register'))

        # Use the prototype for the default role (general)
        default_role = general_user.clone()  # Clone the "general" role

        # Create the user with the default role
        new_user = User(username=username, email=email, role=default_role.role)
        new_user.set_password(password)

        # Save the user to the database
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Find user by email
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id  # Save user ID in session
            session['username'] = user.username  # Save username in session
            session['role'] = user.role  # Save role in session
            return redirect(url_for('home'))
        elif user:
            flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('Email not found. Please register first.', 'danger')

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
@app.route('/guidelines')
def guidelines():
    return render_template('platform_guidelines.html')  # Render the Platform Guidelines page

@app.route('/about')
def about():
    return render_template('about_us.html')  # Render the About Us page


@app.route('/check_news', methods=['GET', 'POST'])
def check_news():
    news_content = None
    language_filter = 'all'

    if request.method == 'POST':
        # Capture the user input
        news_content = request.form['news_content']
        language_filter = request.form['language_filter']

        # Use the Google Fact Check API to verify the news with language filter
        verification_results = verify_news_with_google_api(news_content, language_filter)

        # Render results with an option to create a post
        return render_template(
            'check_news.html',
            news_content=news_content,
            verification_results=verification_results,
            language_filter=language_filter,
        )

    # Initial page load
    return render_template('check_news.html', news_content=news_content, verification_results=None, language_filter=language_filter)



@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    try:
        # Retrieve data from the form
        claim = request.form['claim']
        content = request.form['post_content']
        claimant = request.form.get('claimant', 'Unknown')
        publisher = request.form.get('publisher', 'Unknown publisher')
        rating = request.form.get('textual_rating', 'No rating')

        # Get the user ID from the session
        user_id = session.get('user_id')
        if not user_id:
            flash("You must be logged in to create a post.", "danger")
            return redirect(url_for('login'))

        # Create a new post
        new_post = Post(
            claim=claim,
            content=content,
            claimant=claimant,
            publisher=publisher,
            rating=rating,
            user_id=user_id
        )
        db.session.add(new_post)
        db.session.commit()

        flash("Post created successfully!", "success")
        return redirect(url_for('forum'))

    except Exception as e:
        print("Error:", e)
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('create_post_page'))
from sqlalchemy import func

@app.route('/forum', methods=['GET'])
def forum():
    """
    Forum page displays posts ordered by the number of comments
    and supports searching by claim.
    """
    # Get the search query from the request
    search_query = request.args.get('search', '').strip()

    # Base query for posts
    query = (
        db.session.query(Post, func.count(Comment.id).label('comment_count'))
        .outerjoin(Comment, Comment.post_id == Post.id)
        .group_by(Post.id)
    )

    # Filter by search query if provided
    if search_query:
        query = query.filter(Post.claim.ilike(f"%{search_query}%"))

    # Order by number of comments in descending order
    posts = query.order_by(func.count(Comment.id).desc()).all()

    # Convert query results into a usable format
    forum_posts = [{"post": post, "comment_count": comment_count} for post, comment_count in posts]

    return render_template('forum.html', forum_posts=forum_posts)


@app.route('/forum/<int:post_id>', methods=['GET', 'POST'])
def forum_post(post_id):
    post = Post.query.get_or_404(post_id)

    if request.method == 'POST':
        if 'user_id' not in session:
            return redirect(url_for('login'))

        # Add a new comment
        comment_content = request.form['comment']
        user_id = session.get('user_id')

        new_comment = Comment(content=comment_content, post_id=post.id, user_id=user_id)
        db.session.add(new_comment)
        db.session.commit()

        return redirect(url_for('forum_post', post_id=post_id))

    # Fetch all comments related to the post
    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.timestamp).all()

    return render_template('forum_post.html', post=post, comments=comments)



@app.route('/create_post_page', methods=['GET', 'POST'])
@login_required
def create_post_page():
    """
    Dedicated page for creating a forum post from a fact-check result.
    """
    if request.method == 'POST':
        if 'user_id' not in session:
            return redirect(url_for('login'))

        # Retrieve form data
        claim = request.form['claim']
        claimant = request.form.get('claimant', 'Unknown')
        textual_rating = request.form.get('textual_rating', 'No rating')
        publisher = request.form.get('publisher', 'Unknown publisher')
        post_content = request.form['post_content']

        try:
            # Save the post to the database
            new_post = Post(
                claim=claim,
                content=post_content,
                timestamp=datetime.utcnow()  # Ensure the timestamp is added
            )
            db.session.add(new_post)
            db.session.commit()

            # Redirect to the forum with a success message
            flash("Post created successfully!", "success")
            return redirect(url_for('forum'))
        except Exception as e:
            # Handle errors and provide feedback
            flash(f"An error occurred while creating the post: {e}", "danger")
            return redirect(url_for('create_post_page'))

    # Render the page with pre-filled claim data
    claim = request.args.get('claim', '')
    claimant = request.args.get('claimant', '')
    textual_rating = request.args.get('textual_rating', '')
    publisher = request.args.get('publisher', '')

    return render_template('create_post.html', claim=claim, claimant=claimant, textual_rating=textual_rating, publisher=publisher)

def verify_news_with_google_api(news_content, language_filter='all'):
    """
    Function to query Google Fact Check API and return all results for the provided news content.
    """
    api_url = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
    api_key = "????"  # Replace with your actual API key

    params = {
        "query": news_content,
        "key": api_key,
    }

    # Apply language filter if not "all"
    if language_filter != 'all':
        params["languageCode"] = language_filter

    try:
        # Make the API request
        response = requests.get(api_url, params=params)
        response_data = response.json()

        # Check if claims exist in the response
        if "claims" in response_data:
            claims = response_data["claims"]
            results = []
            for claim in claims:
                text = claim.get("text", "No text available")
                claimant = claim.get("claimant", "Unknown claimant")
                claim_date = claim.get("claimDate", "Unknown date")

                # Get claim review details
                reviews = claim.get("claimReview", [])
                for review in reviews:
                    publisher = review.get("publisher", {}).get("name", "Unknown publisher")
                    site = review.get("publisher", {}).get("site", "Unknown site")
                    url = review.get("url", "#")
                    title = review.get("title", "No title")
                    review_date = review.get("reviewDate", "Unknown review date")
                    textual_rating = review.get("textualRating", "No rating")

                    # Append the result
                    results.append({
                        "text": text,
                        "claimant": claimant,
                        "claim_date": claim_date,
                        "publisher": publisher,
                        "site": site,
                        "url": url,
                        "title": title,
                        "review_date": review_date,
                        "textual_rating": textual_rating,
                    })
            return results
        else:
            return [{"text": "No claims found for this query."}]
    except Exception as e:
        return [{"text": f"Error querying API: {e}"}]

@app.route('/request_role_change', methods=['GET', 'POST'])
@login_required
def request_role_change():
    user_id = session.get('user_id')
    existing_request = RoleRequest.query.filter_by(user_id=user_id, status='pending').first()

    if request.method == 'POST':
        if existing_request:
            flash("You already have a pending role change request. Please wait for it to be reviewed.", "warning")
            return redirect(url_for('request_role_change'))

        role = request.form['role']
        phone = request.form['phone']
        reason = request.form['reason']

        # Create a new role request
        new_request = RoleRequest(user_id=user_id, role=role, phone=phone, reason=reason)
        db.session.add(new_request)
        db.session.commit()

        flash("Your role change request has been submitted successfully!", "success")
        return redirect(url_for('forum'))

    return render_template('request_role_change.html', existing_request=existing_request)


@app.route('/manage_role_requests', methods=['GET', 'POST'])
@login_required
def manage_role_requests():
    # Check if the logged-in user is an admin
    if session['username'] != 'okocta':
        flash("Access denied: You are not authorized to view this page.", "danger")
        return redirect(url_for('forum'))

    # Fetch all pending role requests
    role_requests = RoleRequest.query.filter_by(status='pending').all()

    if request.method == 'POST':
        request_id = request.form['request_id']
        action = request.form['action']  # 'approve' or 'reject'

        # Find the role request
        role_request = RoleRequest.query.get(request_id)
        if role_request:
            if action == 'approve':
                # Update the user's role
                user = User.query.get(role_request.user_id)
                user.role = role_request.role
                role_request.status = 'approved'
                flash(f"Approved role change to '{role_request.role}' for user {user.username}.", "success")
            elif action == 'reject':
                role_request.status = 'rejected'
                flash(f"Rejected role change request from user {role_request.user_id}.", "warning")

            db.session.commit()

    return render_template('manage_role_requests.html', role_requests=role_requests)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    if session.get('username') != 'okocta':
        flash("Access denied: You are not authorized to perform this action.", "danger")
        return redirect(url_for('forum'))

    post = Post.query.get_or_404(post_id)
    try:
        # Delete all comments associated with the post
        Comment.query.filter_by(post_id=post.id).delete()

        # Delete the post itself
        db.session.delete(post)
        db.session.commit()
        flash("Post deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('forum'))


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    if session.get('username') != 'okocta':
        flash("Access denied: You are not authorized to perform this action.", "danger")
        return redirect(url_for('forum'))

    comment = Comment.query.get_or_404(comment_id)
    try:
        db.session.delete(comment)
        db.session.commit()
        flash("Comment deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "danger")

    return redirect(url_for('forum'))


@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if session.get('username') != 'okocta':
        flash("Access denied: You are not authorized to view this page.", "danger")
        return redirect(url_for('forum'))

    users = User.query.filter(User.username != 'okocta').all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        user_to_delete = User.query.get(user_id)
        if user_to_delete:
            try:
                # Delete the user
                db.session.delete(user_to_delete)
                db.session.commit()
                flash(f"User {user_to_delete.username} deleted successfully.", "success")
            except Exception as e:
                flash(f"An error occurred while deleting the user: {e}", "danger")
        else:
            flash("User not found.", "danger")

    return render_template('manage_users.html', users=users)


def initialize_database():
    with app.app_context():
        # Create tables for the user database
        user_engine = db.get_engine(app, bind='user')  # Get the engine for 'user'
        db.metadata.create_all(user_engine)

        # Create tables for the forum database
        forum_engine = db.get_engine(app, bind='forum')  # Get the engine for 'forum'
        db.metadata.create_all(forum_engine)


# Call the function before running the app
if __name__ == "__main__":
    initialize_database()  # Initialize tables
    app.run(debug=True)