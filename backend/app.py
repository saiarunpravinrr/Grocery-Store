from flask import Flask, jsonify, request,session, render_template, send_file, url_for, make_response
from flask_cors import CORS
from flask_restful import Resource, Api
import uuid
from werkzeug.security import  generate_password_hash,check_password_hash
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager,create_access_token, create_refresh_token, jwt_required, get_jwt_identity 
from flask_jwt_extended.exceptions import JWTDecodeError
from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from app1.models import db, User, Admin, Category,Product,Cart,Order
from sqlalchemy import or_
from app1.cache import cache
import app1.config as config
from flask_login import LoginManager,login_user, login_required, logout_user
from datetime import datetime,date,time
from flask_migrate import Migrate,upgrade
from flask_mail import Mail, Message
from email.message import EmailMessage
import schedule
import smtplib
import ssl
#from celery import Celery
#from celery.schedules import crontab
from auth import auth_bp
#from app1.tasks import sendDailyReminderMail, sendMonthReminderMail
import csv
import os

app = Flask(__name__)
app.config.from_object(config)
CORS(app, supports_credentials=True, origins=["http://localhost:8080"])
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 20
#db=SQLAlchemy(app)
db.init_app(app)
jwt.init_app(app)
app.register_blueprint(auth_bp,url_prefix='/auth')

# Define a route to send the daily notification
'''@app.route('/')
def trigger_daily_notification():
    #result = sendDailyReminderMail.apply()
    #result.get()  # Execute the Celery task
    sendDailyReminderMail.delay()
    sendMonthReminderMail.delay()
    
    return "Daily notification task triggered"'''

'''def schedule_tasks():
    # Schedule the daily task to run every day at a specific time (e.g., 7:00 PM)
    schedule.every().day.at("21:16").do(sendDailyReminderMail.apply)

    # Schedule the monthly task to run on the 1st day of every month at a specific time (e.g., 5:00 AM)
    schedule.every().day.at("05:00").do(sendMonthReminderMail.apply)

    # Start the scheduling loop
    while True:
        schedule.run_pending()
        time.sleep(1)

@app.route('/start-scheduling')
def start_scheduling():
    schedule_tasks()  # Start the scheduling process
    return "Scheduling started"'''

# Define email sender and credentials
'''email_sender = 'arunweb635@gmail.com'
email_password = 'awxt quji qatc rpaj'

# Set the subject and body of the email
subject = 'Hello check it out'
body = """We hope you're doing well! We noticed that you haven't visited or made any purchases on our platform recently. We value your presence as a valued customer, and we'd like to remind you of the fantastic products and deals waiting for you.

Take a moment to explore our latest offerings. From fresh groceries to household essentials, we have everything you need. Don't miss out on our special discounts and new arrivals."""

# Add SSL (layer of security)
context = ssl.create_default_context()

# Function to retrieve all user emails from User table
def get_all_user_emails():
    user_emails = User.query.with_entities(User.emailOfUser).all()
    return [email[0] for email in user_emails]

# Run your script within the Flask application context
with app.app_context():
    # Get all user emails
    user_emails = get_all_user_emails()
    email_body = ""
    order_info_list = []
    user_orders = db.session.query(Order, User.emailOfUser).join(User, Order.userId == User.userId).all()
    for order, email in user_orders:
        # Query the Order table to get order information for the user
        
        # Construct the email body with order information
        order_info = "Here is a summary of your recent orders:\n\n"
        order_info += f"Order ID: {order.orderId}\n"
        order_info += f"Payment Method: {order.paymentMethod}\n"
        order_info += f"Payment Method: {order.date}\n"
        order_info += f"Grand Total: ${order.grandtotal}\n\n"
        order_info_list.append(order_info)
        
    email_body = "\n".join(order_info_list)
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email
    em['Subject'] = 'Your Order Information'
    em.set_content(email_body)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, em['To'], em.as_string())

# Loop through the user emails and send emails
for receiver_email in user_emails:
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = receiver_email
    em['Subject'] = subject
    em.set_content(body)

    # Log in and send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, receiver_email, em.as_string())'''
    
#----------------------------------------------------------------------------------------------          
'''@app.route('/')
def index():
    return 'welcome to home page'''
#----------------------------------------------------------------------------------------------
@app.route('/api/signup', methods=['POST'])
def sign_up():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    address = request.json.get('address')
    mobileNumber = request.json.get('mobileNumber')
    if not username or not password or not email or not address or not mobileNumber:
        return jsonify({'message': 'All fields are required'}), 400
    # Check if the email already exists in the database
    existing_user = User.query.filter_by(emailOfUser=email).first()
    USER_id = str(uuid.uuid4())
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400
    new_user = User(userId=USER_id, NameOfUser=username, emailOfUser=email, passwordOfUser=hashed_password, address=address, mobileNumber=mobileNumber) 
    try:
        # Create a new user and add it to the database
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error during signup', 'error': str(e)}), 500
#----------------------------------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    user = User.query.filter_by(emailOfUser=username).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    stored_hash = user.passwordOfUser

    if stored_hash is None:
        return jsonify({'message': 'User has no password set'}), 500

    if bcrypt.check_password_hash(stored_hash, password):
        token = create_access_token(identity=user.userId)
        #token=jwt.encode({'user_id': user.userId,'exp':datetime.datetime.utcnow()+datetime.timedelta(seconds=30)},app.config['SECRET_KEY'])
        return jsonify({'message': 'Login successful', 'access_token': token, 'user_id': user.userId}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

#----------------------------------------------------------------------------------------------          
@app.route('/adminsignup', methods=['POST'])
def admin_signup():
    NameOfadmin = request.json.get('NameOfadmin')
    passwordOfadmin = request.json.get('passwordOfadmin')
    if not NameOfadmin or not passwordOfadmin :
        return jsonify({'message': 'All fields are required'}), 400
    # Check if the email already exists in the database
    existing_admin = Admin.query.filter_by(NameOfadmin=NameOfadmin).first()
    adminId = str(uuid.uuid4())
    if existing_admin:
        return jsonify({'message': 'Admin already registered'}), 400
    new_admin = Admin(adminId=adminId,NameOfadmin=NameOfadmin, passwordOfadmin=passwordOfadmin, is_approved=False)
    try:
        # Create a new user and add it to the database
        db.session.add(new_admin)
        db.session.commit()
        return jsonify({'message': 'Admin registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error during signup', 'error': str(e)}), 500
#----------------------------------------------------------------------------------------------  
@app.route('/admin_requests', methods=['GET'])
def get_admin_requests():
    # Query the database to get admin requests with is_approved equal to false
    admin_requests = Admin.query.filter_by(is_approved=0).all()
    # Serialize the admin requests to JSON
    admin_requests_data = [
        {
            'adminId': request.adminId,
            'NameOfadmin': request.NameOfadmin,
            'is_approved': request.is_approved
        }
        for request in admin_requests
    ]
    return jsonify(admin_requests_data), 200
#----------------------------------------------------------------------------------------------
@app.route('/accept_admin_request/<string:admin_id>', methods=['PUT'])
def accept_admin_request(admin_id):
    # Find the admin request by adminId
    admin_request = Admin.query.get(admin_id)
    if admin_request:
        # Update is_approved to True
        admin_request.is_approved = True
        try:
            db.session.commit()
            return jsonify({'message': 'Admin request accepted'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Error accepting admin request', 'error': str(e)}), 500
    else:
        return jsonify({'message': 'Admin request not found'}), 404
#----------------------------------------------------------------------------------------------
@app.route('/decline_admin_request/<string:admin_id>', methods=['DELETE'])
def decline_admin_request(admin_id):
    # Find the admin request by adminId
    admin_request = Admin.query.get(admin_id)
    if admin_request:
        try:
            # Delete the admin request
            db.session.delete(admin_request)
            db.session.commit()
            return jsonify({'message': 'Admin request declined'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Error declining admin request', 'error': str(e)}), 500
    else:
        return jsonify({'message': 'Admin request not found'}), 404
#----------------------------------------------------------------------------------------------
@app.route('/admin_login', methods=['POST'])
def admin():
    data = request.get_json()
    adminname = data.get('adminname')
    adminpassword = data.get('adminpassword')
    # Check if the admin exists in the database
    admin = Admin.query.filter_by(NameOfadmin=adminname).first()
    if not admin:
        return jsonify({'message': 'Admin not found'}), 404
    # Check if the provided password matches the one in the database
    if admin.passwordOfadmin != adminpassword:
        return {'message': 'Invalid credentials'}, 401
    if admin.is_approved != 1:
        return {'message': 'Admin not approved. Contact the administrator.'}, 401
    # Generate an access token (you can customize the payload as needed)
    access_token = create_access_token(identity=admin.adminId)
    return {'message': 'Login successful', 'access_token': access_token, 'user_role': 'admin' if adminname == 'Admin' else 'manager'}, 200
#----------------------------------------------------------------------------------------------
@app.route('/api/categories', methods=['POST'])
def add_category():
    # Get the data from the request
    category_name = request.json.get('categoryName')
    # Generate a unique categoryId using UUID
    category_id = str(uuid.uuid4())
    # Generate a categoryURLName based on the category name
    category_url_name = category_name.replace(' ', '-').lower()
    # Create a new Category object with the categoryId and categoryURLName
    category = Category(categoryId=category_id, categoryName=category_name, categoryURLName=category_url_name)
    try:
        # Add the category to the database session
        db.session.add(category)
        db.session.commit()
        return jsonify({'message': 'Category saved successfully'})
    except Exception as e:
        db.session.rollback()  # Rollback the transaction
        print(f"Error saving category: {str(e)}")
        return jsonify({'error': 'Error saving the category'})
#----------------------------------------------------------------------------------------------
@app.route('/api/close-db', methods=['POST'])
def close_db_connection():
    try:
        session.clear()
        db.session.close()  # Close the database connection
        return jsonify({"message": "Database connection closed successfully"}), 200
    except Exception as e:
        print("Error closing database:", e)
        return jsonify({"error": "Error closing database connection"}), 500
#----------------------------------------------------------------------------------------------   
@app.route('/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    category_list = []
    for category in categories:
        category_data = {
            'categoryId': category.categoryId,
            'categoryName': category.categoryName,
            'categoryURLName': category.categoryURLName
        }
        category_list.append(category_data)
    return jsonify(category_list)
#----------------------------------------------------------------------------------------------
@app.route('/categories/<string:category_id>', methods=['DELETE'])
def delete_category(category_id):
    category = Category.query.filter_by(categoryId=category_id).first()
    products = Product.query.filter_by(categoryId=category_id).all()
    #product=Product.query.filter_by(categoryId=category_id)
    try:     
        for product in products:
            db.session.delete(product)
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully'})
    except Exception as e:
        db.session.rollback()  # Rollback the transaction
        print(f"Error saving category: {str(e)}")
        return jsonify({'error': 'Error deleting the category'})
#----------------------------------------------------------------------------------------------       
@app.route('/editCategory', methods=['PUT'])
def update_category():
    category_data = request.get_json()
    category_id = category_data['categoryId']
    new_category_name = category_data['categoryName']
    print(new_category_name)
    # Update the category name in the database
    category = Category.query.get(category_id)
    if category is not None:
        category.categoryName = new_category_name
        db.session.commit()
        return jsonify({'message': 'Category updated successfully'})
    else:
        return jsonify({'message': 'Category not found'}), 404  # Return a 404 status code for not found
#----------------------------------------------------------------------------------------------
@app.route('/admin/addproductpage', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        try:
            # Handle the form submission for adding a product
            product_name = request.json.get("productName")
            product_price = request.json.get("productPrice")
            product_unit = request.json.get("productUnit")
            product_quantity = request.json.get("productQuantity")
            category_id = request.json.get("categoryId")
            category_name = request.json.get("categoryName")
            # Create a new Product object with the form data
            product = Product(
                productId=str(uuid.uuid4()),
                productName=product_name,
                productURLName=product_name.replace(' ', '-').lower(),
                productPrice=product_price,
                productUnit=product_unit,
                productQuantity=product_quantity,
                categoryId=category_id,
                categoryName=category_name,
                categoryURLName=category_name.replace(' ', '-').lower()
            )
            # Add the product to the database session
            db.session.add(product)
            db.session.commit()
            return jsonify({'message': 'product saved successfully'})
        except Exception as e:
            db.session.rollback()
            print(f"Error saving product: {str(e)}")
            return jsonify({'error': 'Error saving the product'})
    else:
        # Handle the GET request to display the add product form
        category_id = request.args.get("categoryId")
        category_name = request.args.get("categoryName")      
#----------------------------------------------------------------------------------------------            
@app.route('/products', methods=['GET'])
def get_products():
    category_name = request.args.get('categoryName')
    products = Product.query.filter_by(categoryName=category_name).all()
    products_list = []
    for product in products:
        product_data = {
            'productId': product.productId,
            'productName': product.productName,
            'productPrice': product.productPrice,
            'productUnit': product.productUnit,
            'productQuantity': product.productQuantity,
        }
        products_list.append(product_data)
    return jsonify(products_list)
#----------------------------------------------------------------------------------------------
@app.route('/editProduct', methods=['PUT'])
def update_product():
    product_data = request.get_json()
    product_id = product_data['productId']
    new_product_name = product_data['newProductName']
    new_product_price = product_data['newProductPrice']
    product_unit=product_data['productUnit']
    product_quantity=product_data['productQuantity']
    # Update the product details in the database
    product = Product.query.get(product_id)
    if product is not None:
        product.productName = new_product_name
        product.productPrice = new_product_price
        product.productUnit = product_unit
        product.productQuantity = product_quantity
        product.productURLName=new_product_name.replace(' ', '-').lower()
        # Update other fields as needed
        db.session.commit()
        return jsonify({'message': 'Product updated successfully'})
    else:
        return jsonify({'message': 'Product not found'}), 404  # Return a 404 status code for not found
#----------------------------------------------------------------------------------------------
@app.route('/products/<string:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        product = Product.query.get(product_id)
        if product:     
            db.session.delete(product)
            db.session.commit()
            return jsonify({'message': 'Product deleted successfully'})
        else:
            return jsonify({'error': 'Product not found'}, 404)
    except Exception as e:
        return jsonify({'error': 'Error deleting product', 'details': str(e)}), 500
#----------------------------------------------------------------------------------------------
@app.route('/api/products', methods=['GET'])
def getuser_products():
    user_id = request.args.get('userId')
    user = User.query.filter_by(userId=user_id).first()
    user_name = user.NameOfUser
    products = Product.query.all()
    products_list = []
    for product in products:
        product_data = {
            'productId': product.productId,
            'productName': product.productName,
            'productPrice': product.productPrice,
            'productUnit': product.productUnit,  # Include product unit
            'categoryName':product.categoryName,
        }
        products_list.append(product_data)
    return jsonify(products_list)
#----------------------------------------------------------------------------------------------
@app.route('/api/products-by-category', methods=['GET'])
def get_products_by_category():
    category_name = request.args.get('categoryName')
    # Use category_name to filter products by category and return the filtered products
    # Ensure that you are returning only the products that belong to the specified category.
    products = Product.query.filter_by(categoryName=category_name).all()
    products_list = []
    for product in products:
        product_data = {
            'productId': product.productId,
            'productName': product.productName,
            'productPrice': product.productPrice,
            'productUnit': product.productUnit,  # Include product unit
            'categoryName': product.categoryName,
        }
        products_list.append(product_data)
    return jsonify(products_list)
def generate_unique_item_id(user_id):
    unique_id = str(uuid.uuid4())
    item_id = f"{user_id}_{unique_id}"
    return item_id
#----------------------------------------------------------------------------------------------
@app.route('/api/add-to-cart', methods=['POST'])
def add_to_cart():
    # Get the user ID using current_user.get_id()
    user_id = request.json.get('userId')
    product_id = request.json.get('product_id')
    quantity = int(request.json.get('quantity'))
    # Retrieve the product information
    product = Product.query.get(product_id)
    if product is None:
        return jsonify({'message': 'Product not found'}), 404
    if product.productQuantity < quantity:
        return jsonify({'message': 'Insufficient quantity available'}), 400
    # Check if the item already exists in the cart for the user
    existing_cart_item = Cart.query.filter_by(userId=user_id, productId=product_id, cartActive="True").first()
    if existing_cart_item:
        # Update the quantity and total price of the existing cart item 
        existing_cart_item.productQuantity += quantity
        existing_cart_item.calculate_total_price()
    else:
        # Create a new cart item if it doesn't exist
        item_id = generate_unique_item_id(user_id)
        cart_item = Cart(
            userId=user_id,
            productId=product_id,
            productQuantity=quantity,
            itemId=item_id,
            cartId=user_id,
            cartActive='True',
            productPrice=product.productPrice,
        )
        cart_item.calculate_total_price()
        db.session.add(cart_item)
    db.session.commit()
    return jsonify({'message': 'Product added to cart'}), 200
#----------------------------------------------------------------------------------------------  
@app.route('/api/cart', methods=['GET'])
def get_cart_items():
    # Retrieve the cart items for the current user from the database
    user_id = request.args.get('userId')  # Adjust this based on your authentication mechanism
    cart_items = Cart.query.filter_by(userId=user_id,cartActive='True').all()
    # Create a list to store the serialized cart items
    serialized_cart_items = []
    # Fetch the related product information for each cart item and calculate the total price
    grand_total = 0.0
    for item in cart_items:
        product = Product.query.get(item.productId)
        if product is not None:
            item.productName = product.productName
            item.productPrice = product.productPrice
            item.productQuantity = item.productQuantity
            item.calculate_total_price()  # Update total price calculation
            grand_total += item.totalPrice
            # Serialize the cart item to a dictionary
        serialized_cart_item = {
                'itemId': item.itemId,
                'productName': item.productName,
                'productPrice': item.productPrice,
                'productQuantity': item.productQuantity,
                'totalPrice': item.totalPrice
            }
        serialized_cart_items.append(serialized_cart_item)
    # Return the serialized cart items and grand total as JSON
    response_data = {
        'cartItems': serialized_cart_items,
        'grandTotal': grand_total
    }
    return jsonify(response_data)
#----------------------------------------------------------------------------------------------   
@app.route('/api/cart/delete/<item_id>', methods=['DELETE'])
def delete_cart_item(item_id):
    try:
        # Assuming you have a CartItem model, retrieve the item by its ID
        cart_item = Cart.query.get(item_id)
        if cart_item:
            # Delete the item from the database
            db.session.delete(cart_item)
            db.session.commit()
            return jsonify({'message': 'Item deleted successfully'})
        else:
            return jsonify({'message': 'Item not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
#----------------------------------------------------------------------------------------------
@app.route('/buy-all', methods=['POST'])
def buy_all():
    user_id = request.args.get('userId')
    cart_items = Cart.query.filter_by(userId=user_id, cartActive='True').all()
    for item in cart_items:
        item.cartActive = 'False'
    try:
        # Get the order data from the JSON request
        order_data = request.get_json()
        payment_method = order_data.get('payment_method')
        grand_total = order_data.get('grand_total')
        order_id = str(uuid.uuid4())
        return jsonify({'order_id': order_id, 'grand_total': grand_total, 'success': True})
    except Exception as e:
        # Handle errors, log them, and return an error response
        print('Error:', e)
    return jsonify({'error': 'An error occurred while processing the request.', 'success': False})
#----------------------------------------------------------------------------------------------
@app.route('/place-order', methods=['POST'])
def place_order():
    try:
        # Get the order data from the JSON request
        order_data = request.get_json()
        total_amount = order_data.get('total_amount')
        payment_method = order_data.get('payment_method')
        userId=order_data.get('userId')
        order_id=order_data.get('order_id')
        order = Order(
            orderNumber=order_id,
            userId=userId,
            orderId=order_id,
            cartId=userId,  # Or any other identifier for the cart
            paymentMethod=payment_method,
            date=date.today(),  # Use Python date object instead of string
            grandtotal=total_amount,
        )
        # Save the order to the database
        db.session.add(order)
        # Mark the cart items as inactive (cartActive='False')
        cart_items = Cart.query.filter_by(userId=userId,cartActive='True').all()
        for item in cart_items:
            item.cartActive = 'False'
            # Update the product quantity in the database after placing the order
            product = Product.query.get(item.productId)
        if product:
            product.productQuantity -= item.productQuantity
        db.session.commit()
        # Return a success response
        return jsonify({'success': True, 'order_id': order_id})
    except Exception as e:
    # Handle errors, rollback the session, and return an error response
        db.session.rollback()
        print('Error:', e)
        return jsonify({'error': 'An error occurred while processing the request.', 'success': False})
#---------------------------------------------------------------------------------------------- 
@app.route('/profile', methods=['GET'])
def profile():
    user_id = request.args.get('userId')
    user = User.query.filter_by(userId=user_id).first()
    user_name = user.NameOfUser
    orders = Order.query.filter_by(userId=user_id).all()
    # Convert orders to a JSON-like format for easier serialization to Vue
    orders_data = [{'orderNumber': order.orderId,
                'grandtotal': order.grandtotal,
                'paymentMethod': order.paymentMethod,
                'date': order.date} for order in orders]
    response_data={'user_name':user_name,'orders': orders_data}
    return jsonify(response_data)
#----------------------------------------------------------------------------------------------
@app.route('/search', methods=['GET'])
def search_products():
    query = request.args.get('query')
    if query:
        
        # Check if the entered query is a category name
        category = Category.query.filter_by(categoryName=query).first()
        if category:
            # If it's a category name, get all products belonging to that category
            filtered_products = category.products
            filtered_categories = [category.categoryName]  # Create a list of category names
        else:
            # If it's not a category name, perform a combined search based on the query
            product_search = Product.query.filter(Product.productName.ilike(f'%{query}%'))
            category_search = Category.query.filter(Category.categoryName.ilike(f'%{query}%')).first()

            # Combine the results of product and category searches
            filtered_products = product_search.all()
            if category_search:
                filtered_products.extend(category_search.products)

            filtered_categories = list(set([product.category.categoryName for product in filtered_products]))
    else:
        # If no search query, display all products and categories
        all_products = Product.query.all()
        all_categories = [product.category.categoryName for product in all_products]
        filtered_products = all_products
        filtered_categories = list(set(all_categories))
    
    filtered_products_data = []
    for product in filtered_products:
        serialized_product = {
            'productId': product.productId, 
            'productName': product.productName,
            'productPrice': product.productPrice,
            'productUnit': product.productUnit, 
            'categoryName': product.category.categoryName
        }
        filtered_products_data.append(serialized_product)
    
    response_data = {
        'filteredProducts': filtered_products_data,
        'filteredCategories': filtered_categories
    }     

    print(f"Category search result: {category_search}")

    # Return the JSON response
    return jsonify(response_data)
#--------------------------------------------------------------------------------------------------
@app.route('/manager/export-products-csv', methods=['GET'])
def export_products_csv():
    try:
        # Query the Product model to fetch product data
        products = Product.query.all()

        # Define the CSV file path with a timestamp
        now = datetime.now().strftime("%d-%m-%Y_%H%M")
        product_filename = f'products_{now}.csv'
        csv_path = os.path.join(app.root_path, 'static', 'CSV exports', 'products', product_filename)

        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)

        # Create and write to the CSV file
        with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)

            # Define the product fields (column headers)
            product_fields = ['ID', 'Product Name', 'Quantity', 'Price']
            csv_writer.writerow(product_fields)

            # Write product data to the CSV file
        for product in products:
            row = [product.productId, product.productName, product.productQuantity, product.productPrice]
            csv_writer.writerow(row)

        # Serve the CSV file as a downloadable response with the attachment filename set
        response = send_file(
            csv_path,
            as_attachment=True,
            mimetype='text/csv'
        )
        response.headers["Content-Disposition"] = f"attachment; filename={product_filename}"
        return response
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    app.run(debug=True)

