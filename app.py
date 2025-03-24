# app.py
import os
import subprocess
import logging
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# Configure logging
logging.basicConfig(
    filename='redirect.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///redirects.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['NGINX_MAP_FILE'] = os.environ.get('NGINX_MAP_FILE', '/etc/nginx/redirects.map')

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Redirect(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_path = db.Column(db.String(200), unique=True, nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

# Authentication Utilities
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def update_nginx_map():
    """Updates the Nginx map file with current redirection rules and reloads Nginx."""
    redirects = Redirect.query.all()
    logging.info(f"Updating Nginx map with {len(redirects)} redirect rules")
    
    nginx_map_file = app.config['NGINX_MAP_FILE']
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(nginx_map_file), exist_ok=True)
        
        with open(nginx_map_file, 'w') as f:
            for redirect_rule in redirects:
                f.write(f'"{redirect_rule.original_path}" "{redirect_rule.target_url}";\n')
                logging.debug(f"Added redirect rule to map: {redirect_rule.original_path} -> {redirect_rule.target_url}")
        
        # Output to a log file as well for debugging
        with open('nginx_updates.log', 'a') as log:
            log.write(f"{datetime.datetime.now()} - Updated {len(redirects)} redirects\n")
        
        try:
            # Reload Nginx to apply changes
            # For development environments where sudo might not be available
            if os.path.exists('/usr/sbin/nginx'):
                subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], check=True)
                logging.info("Successfully reloaded Nginx")
                return True
            else:
                logging.warning("Nginx reload skipped in development environment")
                flash('Nginx reload skipped in development environment.', 'warning')
                return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to reload Nginx: {str(e)}")
            flash(f'Failed to reload Nginx: {str(e)}. Please check system permissions.', 'danger')
            return False
    except Exception as e:
        logging.error(f"Failed to update Nginx map file: {str(e)}")
        flash(f'Failed to update Nginx map file: {str(e)}', 'danger')
        return False

# Main route - handles redirections
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    # Log the incoming request
    full_path = '/' + path if path else '/'
    logging.info(f"Received request for path: {full_path}")
    
    # Check if path exists in our database
    redirect_rule = Redirect.query.filter_by(original_path=full_path).first()
    
    if redirect_rule:
        logging.info(f"Found redirect rule: {redirect_rule.original_path} -> {redirect_rule.target_url}")
        # Add cache control headers to prevent caching
        response = redirect(redirect_rule.target_url, code=302)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    else:
        logging.info(f"No redirect rule found for path: {full_path}")
        # If not an admin route and no redirect found, show 404
        if not request.path.startswith('/admin') and not request.path.startswith('/login'):
            flash('The requested page was not found.', 'danger')
            return render_template('404.html'), 404
    
    # For admin routes, continue normal processing
    return None

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    redirects = Redirect.query.order_by(Redirect.original_path).all()
    return render_template('admin_dashboard.html', redirects=redirects)

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def add_redirect():
    if request.method == 'POST':
        original_path = request.form['original_path']
        target_url = request.form['target_url']
        
        # Ensure the original path starts with a slash
        if not original_path.startswith('/'):
            original_path = '/' + original_path
        
        # Check if this path already exists
        existing = Redirect.query.filter_by(original_path=original_path).first()
        if existing:
            flash(f'A redirect for "{original_path}" already exists.', 'danger')
            return redirect(url_for('add_redirect'))
        
        new_redirect = Redirect(original_path=original_path, target_url=target_url)
        db.session.add(new_redirect)
        
        try:
            db.session.commit()
            if update_nginx_map():
                flash('Redirect added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding redirect: {str(e)}', 'danger')
    
    return render_template('add_redirect.html')

@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_redirect(id):
    redirect_rule = Redirect.query.get_or_404(id)
    logging.info(f"Editing redirect rule: {redirect_rule.original_path} -> {redirect_rule.target_url}")
    
    if request.method == 'POST':
        original_path = request.form['original_path']
        target_url = request.form['target_url']
        
        # Ensure the original path starts with a slash
        if not original_path.startswith('/'):
            original_path = '/' + original_path
            
        # Check if updating would create a duplicate
        existing = Redirect.query.filter_by(original_path=original_path).first()
        if existing and existing.id != id:
            logging.warning(f"Duplicate redirect path detected: {original_path}")
            flash(f'A redirect for "{original_path}" already exists.', 'danger')
            return redirect(url_for('edit_redirect', id=id))
        
        old_target = redirect_rule.target_url
        redirect_rule.original_path = original_path
        redirect_rule.target_url = target_url
        
        try:
            db.session.commit()
            logging.info(f"Updated redirect rule: {original_path} from {old_target} to {target_url}")
            if update_nginx_map():
                flash('Redirect updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating redirect: {str(e)}")
            flash(f'Error updating redirect: {str(e)}', 'danger')
    
    return render_template('edit_redirect.html', redirect=redirect_rule)

@app.route('/admin/delete/<int:id>', methods=['POST'])
@login_required
def delete_redirect(id):
    redirect_rule = Redirect.query.get_or_404(id)
    
    try:
        db.session.delete(redirect_rule)
        db.session.commit()
        if update_nginx_map():
            flash('Redirect deleted successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting redirect: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Command to create initial admin user
@app.cli.command('create-admin')
def create_admin():
    """Create an admin user."""
    import click
    username = click.prompt('Username')
    password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
    
    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        click.echo('User already exists!')
        return
    
    user = User(username=username)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    click.echo('Admin user created successfully!')

# Initialize the database
@app.cli.command('init-db')
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized.')

# Command to test Nginx map file generation
@app.cli.command('test-nginx')
def test_nginx():
    """Test Nginx map file generation without actually reloading Nginx."""
    import click
    
    try:
        redirects = Redirect.query.all()
        click.echo(f"Found {len(redirects)} redirect rules")
        
        test_file = 'test_redirects.map'
        with open(test_file, 'w') as f:
            for redirect_rule in redirects:
                f.write(f'"{redirect_rule.original_path}" "{redirect_rule.target_url}";\n')
        
        click.echo(f"Test file generated: {test_file}")
        click.echo("Content:")
        with open(test_file, 'r') as f:
            click.echo(f.read())
    except Exception as e:
        click.echo(f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True)