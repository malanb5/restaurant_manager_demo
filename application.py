"""
    ShopMe - A Demo Catalog website

    A demo website for posting, editing, and deleting a variety
    of catalog items.  Using virtualbox and vagrant as a virtual environment.

"""

from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response, jsonify
import requests
from functools import wraps


app = Flask(__name__)

"""
Connects to sqlite database using sqlalchemy API
"""

engine = create_engine('sqlite:///catalogapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# set contant variables
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "ShopMe"


# Check to see if the user is logged in, decorator function
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not permission():
            flash("Please log-in")
            return redirect('login')
        return f(*args, **kwargs)
    return decorated_function


"""
Google OAuth login and disconnection methods
"""


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Connect google+ account."""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """
        " style = "width: 80px; height: 80px;border-radius: 50%;
         -webkit-border-radius: 50%;-moz-border-radius: 50%;"> '
         """
    flash("Welcome, you are now logged in as %s." % login_session['username'])

    return output


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # del login_session['access_token']
        # del login_session['gplus_id']
        # del login_session['username']
        # del login_session['email']
        # del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token '
                                            'for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


"""
Routing methods
"""


@app.route('/')
@app.route('/catalogs/')
def home():
    """
    The home page
    create an anti-forgery state token to prevent cross-site request forgery
    :return: returns the home screen
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('home.html', STATE=state, all_categories=categories(),
                           latest_items=items(count='latest'),
                           show_categories=True)


@app.route('/catalogs/<category_name>/')
@app.route('/catalogs/<category_name>/items/')
def showCategory(category_name):
    """
    List all items in the selected category
    """
    return render_template(
        'show.html',
        category_name=category_name,
        all_categories=categories(),
        filtered_items=items(category_name=category_name),
        show_categories=True)


@app.route('/catalogs/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
    Create a new category
    """
    if request.method == 'POST':

        new_category_name = request.form['name'].strip()
        if new_category_name:
            new_category = Category(name=new_category_name,
                                    user=getUserInfo(login_session['user_id']))
            session.add(new_category)

            """
            Check to see if the name is in the database
            If so then commit changes, if not roll back
            """
            try:
                session.commit()
                flash("Category is successfully created.")
                return redirect(url_for('showCategory',
                                        category_name=new_category_name))
            except IntegrityError:
                session.rollback()
                errors = {'name': "already exists, try different name"}
                # show user-entered non-unique value in the form
                values = {'name': request.form['name']}
                return render_template('new.html',
                                       errors=errors, values=values)
        else:
            errors = {'name': "Please enter valid name"}
            return render_template('new.html', errors=errors)
    else:
        return render_template('new.html')


@app.route('/catalogs/<category_name>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_name):
    """
    Allow logged in users to edit a category
    """

    category_to_edit = category(category_name)
    if not permissionEdit(category_to_edit):
        flash("""You do not have permission to edit this.
        Please log in as the correct user""")

        return redirect('/')

    if request.method == 'POST':
        edited_category_name = request.form['name'].strip()
        if edited_category_name:
            # if not blank, update it
            category_to_edit.name = edited_category_name
            session.add(category_to_edit)
            try:
                session.commit()
                flash("Category is successfully updated.")

                return redirect(
                    url_for(
                        'showCategory',
                        category_name=edited_category_name))
            except IntegrityError:
                # name must be unique, so re-render form with this error
                session.rollback()
                errors = {'name': "already exists, try different name"}
                # show user-entered non-unique value in the form
                values = {'name': request.form['name']}
                return render_template(
                    'edit.html',
                    category=category_to_edit,
                    errors=errors,
                    values=values)
        else:
            # if it's blank, re-render form with errors
            errors = {'name': "Can notbe blank"}
            return render_template(
                'edit.html',
                category=category_to_edit,
                errors=errors)
    else:
        # Show a form to edit a category
        return render_template(
            'edit.html',
            category=category_to_edit)


@app.route('/catalogs/<category_name>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_name):
    """
    Allow logged users to delete a category (and items in it)
    """
    # check user is the correct one
    category_to_delete = category(category_name)
    if not permissionEdit(category_to_delete):
        flash("""You do not have permission to edit this.
        Please log in as the correct user""")

        return redirect('/')

    items_to_delete = items(category_name=category_name)
    # check user is owner of the all items in that category
    for item_to_delete in items_to_delete:
        if not permissionEdit(item_to_delete):
            flash("""You do not have permission to delete these items.""")
            return redirect('/')

    if request.method == 'POST':
        # Delete category and related items
        for item_to_delete in items_to_delete:
            session.delete(item_to_delete)
        session.delete(category_to_delete)
        try:
            session.commit()
            flash("Successfully deleted category.")
            return redirect('/')
        except(Exception):
            session.rollback()
            return "An unknown error occured!"
    else:
        # Show a confirmation to delete
        return render_template(
            'delete.html',
            category_name=category_name)


@app.route('/catalogs/<category_name>/items/<item_name>/')
def showItem(category_name, item_name):
    """
    Show details of selected item
    """
    item_to_show = item(item_name, category_name)
    return render_template('items/show.html', item=item_to_show)


@app.route('/catalogs/<category_name>/items/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_name):
    """
    Creates a new item
    """

    if request.method == 'POST':
        new_item_name = request.form['name'].strip()
        new_item_description = request.form['description'].strip()
        if new_item_name and new_item_description:
            # if not blank, save to database
            try:
                # if same item in that category, re-render with error
                item(name=new_item_name, category_name=category_name)
                errors = {
                    'name': 'another item has same name, and same category'}
                params = {
                    'name': new_item_name,
                    'description': new_item_description}
                return render_template(
                        'items/new.html',
                        category_name=category_name,
                        errors=errors,
                        params=params)
            except(Exception):
                new_item = Item(
                    name=new_item_name,
                    description=new_item_description,
                    category=category(category_name),
                    user=getUserInfo(login_session['user_id']))
                session.add(new_item)
                session.commit()
                flash("Item is successfully created.")
                return redirect(
                    url_for(
                        'showItem',
                        category_name=category_name,
                        item_name=new_item_name))
        else:
            errors = {}
            # store user-entered data to show them in re-rendered form
            params = {'name': '', 'description': ''}
            if new_item_name:
                params['name'] = new_item_name
            else:
                errors['name'] = "Cannot be blank"

            if new_item_description:
                params['description'] = new_item_description
            else:
                errors['description'] = "Cannot be blank"

            return render_template(
                'items/new.html',
                category_name=category_name,
                errors=errors,
                params=params)
    else:
        # Show a form to create new item
        return render_template(
            'items/new.html',
            category_name=category_name,
            params={'name': '', 'description': ''})


@app.route(
    '/catalogs/<category_name>/items/<item_name>/edit/',
    methods=['GET', 'POST'])
@login_required
def editItem(category_name, item_name):
    """
    Method for editing an item
    """

    item_to_edit = item(item_name, category_name)

    if not permissionEdit(item_to_edit):
        flash("""You do not have permission to edit this.
        Please log in as the correct user""")

        return redirect('/')

    if request.method == 'POST':
        # Update item
        edited_item_name = request.form['name'].strip()
        edited_item_description = request.form['description'].strip()
        if edited_item_name and edited_item_description:
            item_to_edit.name = edited_item_name
            item_to_edit.description = edited_item_description
            session.add(item_to_edit)
            try:
                session.commit()
                flash("Item is successfully updated.")

                return redirect(
                    url_for(
                        'showItem',
                        category_name=category_name,
                        item_name=edited_item_name))

            except IntegrityError:
                session.rollback()
                errors = {'name': "already exists, try different name"}
                # show user-entered non-unique value in the form
                values = {'name': request.form['name']}
                return render_template('items/edit.html',
                                       category_name=category_name,
                                       item_name=item_name,
                                       errors=errors, params=params)
        else:
            errors['name'] = "Error cannot be blank"

        if edited_item_description:
            params['description'] = edited_item_description
        else:
            errors['description'] = "Error cannot be blank"

        return render_template('items/edit.html',
                               category_name=category_name,
                               item_name=item_name,
                               errors=errors,
                               params=params)
    else:
        # Show a form to edit item
        return render_template(
            'items/edit.html',
            category_name=category_name,
            item_name=item_name,
            params={'name': item_to_edit.name,
                    'description': item_to_edit.description})


@app.route(
    '/catalogs/<category_name>/items/<item_name>/delete/',
    methods=['GET', 'POST'])
@login_required
def deleteItem(category_name, item_name):

    """
    Allow logged users to delete an item
    """

    item_to_delete = item(item_name, category_name)

    # check user is towner of the item
    if not permissionEdit(item_to_delete):
        flash("""Permission denied, please login with\
        the correct identity to edit""")

        return redirect('/')

    if request.method == 'POST':
        # Delete item
        session.delete(item_to_delete)
        try:
            session.commit()
            flash("Successfully deleted")

            return redirect(
                url_for('showCategory', category_name=category_name))
        except(Exception):
            session.rollback()
            return "An error occurred, no changes were made"
    else:
        # Show a confirmation to delete
        return render_template(
            'items/delete.html',
            category_name=category_name,
            item_name=item_name)


# Disconnect routing
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect('/')
    else:
        flash("You were not logged in")
        return redirect('/')


"""
Helper functions to check user information
"""


# Create new user and return its id
def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Find user with an id and return the user
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Find user with an email and return the user
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except(Exception):
        return None


# Check any user logged in
def permission():
    return 'username' in login_session


# Check user owner of a thing(category or item)
def permissionEdit(item):
    return ('user_id' in login_session and
            item.user_id == login_session['user_id'])


# Inject user_logged_in in templates to check any user logged in
@app.context_processor
def inject_user_logged_in():
    return dict(user_logged_in=permission())


# Find a category using its name and return it
def category(category_name):
    return session.query(Category).filter_by(name=category_name).one()


# Return all categories in the database
def categories():
    return session.query(Category).order_by('name')


# Find an item using its name and category name, then return it
def item(name, category_name):
    return session.query(Item).filter_by(
        name=name,
        category_id=category(category_name).id).one()


# Filter items with given parameters(how many, their category)
def items(count='all', category_name=None):
    # Latest 10 items
    if count == 'latest':
        return session.query(Item).order_by(desc('id')).limit(10)
    elif category_name:
        current_category = category(category_name)
        filtered_items = session.query(Item).filter_by(
            category_id=current_category.id)
        # Items filtered by their category names
        return filtered_items.order_by('name')
    else:
        # All items in the database
        return session.query(Item).order_by('name')


"""
Add JSON API Endpoints
"""


# JSON API for catalog
@app.route('/catalogs/<category_name>/items/JSON')
def CatalogItemsJSON(category_name):
    json_items = items(category_name=category_name)
    return jsonify(CategoryItems=[i.serialize for i in json_items])


# JSON API for item
@app.route('/catalogs/<category_name>/items/<item_name>/JSON')
def ItemJSON(category_name, item_name):
    json_item = item(item_name, category_name)
    return jsonify(CategoryItem=json_item.serialize)


if __name__ == '__main__':
    app.secret_key = 'secretkey'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
