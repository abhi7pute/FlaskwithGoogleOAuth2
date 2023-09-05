from flask import Flask, render_template, redirect, session, request, jsonify, url_for
from flask_oauthlib.client import OAuth
from datetime import datetime, timedelta

app = Flask(__name__)

# OAuth Configuration
app.secret_key = 'your-secret-key'  # Replace with a strong secret key
oauth = OAuth(app)

# Google OAuth Configuration
google = oauth.remote_app(
    'google',
    consumer_key='265644495405-quhqcq5is8kobr964diqt9a9ar3ljjfq.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

# Sample user data (you should replace this with your user management logic)
users = {
    'user1@example.com': {
        'email': 'user1@example.com',
        'name': 'User One',
    }
}

# Use a dictionary to store request timestamps per IP address
request_history = {}

# Define a rate limit (e.g., 5 requests per minute)
RATE_LIMIT = 5
RATE_LIMIT_PERIOD = 60  # seconds

@app.before_request
def limit_requests():
    client_ip = request.remote_addr
    current_time = datetime.now()

    if client_ip not in request_history:
        request_history[client_ip] = [current_time]
    else:
        # Remove timestamps older than the rate limit period
        request_history[client_ip] = [
            t for t in request_history[client_ip] if current_time - t <= timedelta(seconds=RATE_LIMIT_PERIOD)
        ]

    if len(request_history[client_ip]) > RATE_LIMIT:
        return jsonify({"message": "Rate limit exceeded"}), 429

# Login Route: Redirect to Google OAuth Login
@app.route('/login')
def login():
    return google.authorize(callback=url_for('google_authorized', _external=True))

# Callback Route: Handle the callback from Google
@app.route('/login/google/authorized')
def google_authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['google_token'] = (response['access_token'], '')

    # Retrieve user information from the OAuth provider (Google)
    user_info = google.get('userinfo')

    if user_info.data.get('email'):
        # Check if the user already exists in your database (based on email)
        existing_user = users.get(user_info.data['email'])

        if existing_user:
            # User already exists, do nothing or update user information
            pass
        else:
            # User doesn't exist, create a new user profile in your database
            # For example, you can add a new user to your 'users' dictionary
            # or use a database like SQLAlchemy to store user profiles.
            users[user_info.data['email']] = {
                'email': user_info.data['email'],
                'name': user_info.data['name'],
            }

    # Redirect to the main page or a dashboard
    return redirect(url_for('http://localhost:5000/google_login'))

# Logout Route: Clear the Google OAuth Token and the session
@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))

# Main Page
@app.route('/')
def index():
    if 'google_token' in session:
        return render_template('dashboard.html', user_info=google.get('userinfo').data)
    else:
        return render_template('home.html')

# Protected Route: Example of a route that requires authentication
@app.route('/protected')
def protected_route():
    if 'google_token' in session:
        # User is authenticated, allow access to protected functionality
        return "This is a protected page. You are authenticated."
    else:
        # User is not authenticated, redirect to login page or show an error message
        return "Access denied. Please log in to access this page."

if __name__ == '__main__':
    app.run(debug=True)
