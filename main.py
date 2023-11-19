from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, session, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from forms import InventoryForm, RegisterForm, LoginForm
from flask_session import Session
import stripe


stripe.api_key = 'pk_test_51ODewvIlrA5L99MBXvP71qe65tMvhV9qC8aLRR8HPygAtWs9MCaEJD2tLlUNIcGGgcsd3CkZK5UI4ILzEnnH2H9X00XT6iDOSb'
STRIPE_ENDPOINT = 'https://api.stripe.com'

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

YOUR_DOMAIN = 'http://127.0.0.1:5001'
CART = []

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///online_shop.db'
db = SQLAlchemy()
db.init_app(app)


# User Table
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, unique=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), nullable=False)
    orders = relationship('OrderHistory', back_populates='user')


class Inventory(db.Model):
    __tablename__ = 'inventory'
    product_id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(250), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    orders = relationship('OrderHistory', back_populates='product')


class OrderHistory(db.Model):
    __tablename__ = 'order_history'
    order_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('inventory.product_id'))
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.String(250), nullable=False)
    user = relationship('User', back_populates='orders')
    product = relationship('Inventory', back_populates='orders')


with app.app_context():
    db.create_all()


# Create an admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
            # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# Stripe Check-out
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        cart_items = [int(item) for item in CART]

        # Get product information for each item in the cart
        line_items = []
        for product_id in cart_items:
            product = Inventory.query.get(product_id)
            if product:
                # Assuming 'price_id' is a field in your Inventory model
                price_id = product.product_id  # Replace with the actual field name
                line_items.append({
                    'price': price_id,
                    'quantity': 1,
                })

        checkout_session = stripe.checkout.Session.create(
            line_items=line_items,
            mode='payment',
            success_url=YOUR_DOMAIN + '/success.html',
            cancel_url=YOUR_DOMAIN + '/cancel.html',
        )
    except Exception as e:
        return str(e)

    return render_template(checkout_session.url, code=303)


@app.route('/order/success')
def success():
    return render_template('success.html')


@app.route('/order/cancel')
def cancel():
    return render_template('cancel.html')


@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = []
    session['cart'].append(product_id)
    return redirect(url_for('show_cart'))


@app.route('/show_cart')
def show_cart():
    if not session.get("name"):
        return redirect("/login")
    if 'total' not in session:
        session['total'] = 0
    cart_items = session.get('cart', [])
    products_in_cart = Inventory.query.filter(Inventory.product_id.in_(cart_items)).all()
    for product in products_in_cart:
        session['total'] += product.price
    return render_template('show_cart.html', products_in_cart=products_in_cart,total=session['total'], current_user=current_user)


# Register new users into the User database
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("index"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
            # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            session["name"] = form.password.data
            login_user(user)
            return redirect(url_for('index'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    session["name"] = None
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    result = db.session.execute(db.select(Inventory))
    inventory = result.scalars().all()
    return render_template("index.html", inventory=inventory, current_user=current_user)


# Use a decorator so only an admin user can create new posts
@app.route("/inventory", methods=["GET", "POST"])
@admin_only
def inventory():
    form = InventoryForm()
    if form.validate_on_submit():
        # Check if item is already present in the database.
        result = db.session.execute(db.select(Inventory).where(Inventory.product_name == form.product_name.data))
        item = result.scalar()
        if item:
            flash("That item is already in the db")
            return redirect(url_for('inventory'))
        new_item = Inventory(
            product_name=form.product_name.data,
            price=form.price.data,
            quantity=form.quantity.data,
        )
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("make-show_cart.html", form=form, current_user=current_user)


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(Inventory, post_id)
    edit_form = InventoryForm(
        product_name=post.product_name,
        price=post.price,
        quantity=post.quantity,
    )
    if edit_form.validate_on_submit():
        post.product_name = edit_form.product_name.data
        post.price = edit_form.price.data
        post.quantity = edit_form.quantity.data
        db.session.commit()
        return redirect(url_for("index"))
    return render_template("make-show_cart.html", form=edit_form, is_edit=True, current_user=current_user)


# Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    item_to_delete = db.get_or_404(Inventory, post_id)
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('index'))


@app.route("/about")
def about():
    if not session.get("name"):
        return redirect("/login")
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5001)