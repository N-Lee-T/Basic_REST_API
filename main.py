"""
Nathan Thompson
thomnath@oregonstate.edu
CS 493 Cloud - Spring 2023
Final project
"""

import os
import requests
import uuid
import json
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, url_for, render_template, redirect, request, make_response, session
from six.moves.urllib.request import urlopen
from six.moves.urllib.parse import urlencode
from functools import wraps
from jose import jwt 
from flask_cors import cross_origin # do we need cross-origin resource sharing? I guess?
from google.cloud import datastore #, firestore
from json2html import json2html #needed?
from authlib.integrations.flask_client import OAuth
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
# from uuid import uuid4

app = Flask(__name__)

client = datastore.Client()

USERS = 'users'
BOOKS = 'books'
LIBRARIES = 'library'

# book_cursor = None
# library_cursor = None

# save_info = firestore.Client()
# sessions = save_info.collection('sessions')

# get / set environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
DOMAIN = os.environ.get('DOMAIN')

ALGORITHMS = ["RS256"]

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY') #str(uuid.uuid4())

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{os.environ.get("DOMAIN")}/.well-known/openid-configuration'

)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def verify_jwt(token):
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# for book & library routes, checks the header first, then calls func to verify JWT
def check_jwt_first(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return False #({"Error": "Credentials missing or invalid"}, 401) 
        # return AuthError({"Error": "Credentials missing or invalid"}, 401) 
    return verify_jwt(token)

"""
Main page  & user information
"""

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route("/login")
def login():
    # at login, initialize cursor to view books 
    # session['book_cursor'], session['library_cursor'] = None, None
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("display_user", _external=True)
    )

@app.route('/userinfo', methods=['GET', 'POST'])
def display_user():
    # save the token information in Datastore as a User entity & return info to webpage
    token = oauth.auth0.authorize_access_token()
    new_user = datastore.entity.Entity(key=client.key(USERS))       
    new = {
            "name": token['userinfo']['name'], 
            "email": token['userinfo']['email'], 
            "sub": token['userinfo']['sub'],
            "token": token['id_token'],
            "nickname": token['userinfo']['nickname'],
            "libraries": [],
            } 
    new_user.update(new)
    client.put(new_user)
    new['datastore_id'] = new_user.key.id
    new['self'] = request.base_url + '/users/' + str(new_user.key.id)
    print(new)
    return(render_template('userinfo.html', datastoreID=new['datastore_id'],
                                            name=new['nickname'], 
                                            email=new['email'], 
                                            sub=new['sub'], 
                                            libraries=new['libraries'],  
                                            token=new['token']),
                                            201)

@app.route('/users', methods=['GET'])
def get_them_users():
    if 'application/json' not in request.accept_mimetypes: 
        return({"Error":  "Only JSON media can be requested"}, 406)
    user_query = client.query(kind=USERS)
    user_results = list(user_query.fetch())
    try: 
        request.get_json()
        return ({"Error": "Not found: cannot search for unique user or parameters"}, 404) 
    except:
        return (json.dumps(user_results), 200)
    

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )


"""
book and library endpoints
"""

@app.route('/books', methods=["POST", "GET"])
def book_me():
    if request.method == "DELETE":
        return({"Error":"Deleting all objects is not allowed. Include a book_id in your request"}, 405)
    if 'application/json' not in request.accept_mimetypes: 
        return({"Error":  "Only JSON media can be requested"}, 406)
    # get list of book objects from Datastore
    query = client.query(kind=BOOKS)
    book_results = list(query.fetch())
    book_total = len(book_results)
    if request.method == "POST":
        # only authorized users can create books
        payload = check_jwt_first(request)
        if payload:
            content = request.get_json()
            # check for duplicate titles
            for each in book_results:
                if each["title"] == content["title"]:
                    return ({"Error": "Duplicate book name detected"}, 403)
            new_book = datastore.entity.Entity(key=client.key(BOOKS))    
            for each in content:
                if each not in ['title', 'author', 'genre']:
                    return ({"Error":"'author', 'title', and 'genre' are required and are the only acceptable attributes"}, 400)   
            new = {
                    "title": content['title'], 
                    "author": content['author'], 
                    "genre": content['genre'],
                    "library": [],
                    } 
            new_book.update(new)
            client.put(new_book)
            new['id'] = new_book.key.id
            new['self'] = request.base_url + '/' + str(new_book.key.id)
            return (new, 201)
        else:
            return({"Error": "You do not have permission to create a book"}, 401)
    elif request.method == 'GET':
        those_books = []
        query_limit = 5
        if request.args.get('offset'):
            query_offset = int(request.args.get('offset'))
        else:
            query_offset = 0
        the_iterator = query.fetch(limit=query_limit, offset=query_offset)
        pages = the_iterator.pages
        book_results = list(next(pages))
        if the_iterator.next_page_token:
            next_offset = query_offset + query_limit
            next_url = request.base_url + "?limit=" + str(query_limit) + "&offset=" + str(next_offset)
        else: 
            next_url = None
        for e in book_results:
            e['id'] = e.key.id
            those_books.append(e)
        start = query_offset + 1
        if (query_offset+query_limit) <= book_total:
            max = (query_offset+query_limit)
        else: max = book_total
        final = {
            # "Viewing": str(query_offset) + " through " + str(query_offset+query_limit) + " of " + str(book_total),
            "Viewing": str(start) + " through " + str(max) + " of " + str(book_total),
            "next": next_url,
            "books": those_books
        }
        return (final, 200)
    else:
        return({"Error": "The method you are trying is not allowed"}, 405)
    
@app.route('/books/<book_id>', methods=['GET','DELETE'])
def one_book(book_id):
    book_key = client.key(BOOKS, int(book_id))
    book = client.get(key=book_key)
    if not book:
        return ({"Error": "No book with that book_id was found in the database. Check your book_id and try again"}, 404)
    if request.method == 'DELETE':
        if not book_id:
            return({"Error":"Deleting all objects is not allowed. Include a book_id in your request"}, 405)
        if not check_jwt_first(request):
            return ({"Error": "You do not have permission to delete this book"}, 401)
    # go thru the libraries to which the book has been added & delete the book from them
        for library in book['library']:
            library_key = client.key(LIBRARIES, int(library))
            update_library = client.get(key=library_key)
            update_library['books'].remove(int(book_id))
            client.put(update_library)
        client.delete(book_key)
        return ('', 204)
    return(json.dumps(book), 200)
    # return render_template('boats.html', boats=boats)

@app.route('/libraries', methods=['GET', 'POST'])
def make_that_lib():
    if request.method == "DELETE":
        return({"Error":"Deleting all objects is not allowed. Include a book_id in your request"}, 405)
    if 'application/json' not in request.accept_mimetypes: 
        return({"Error":  "Only JSON media can be requested"}, 406)
    if request.method == "POST":
        payload = check_jwt_first(request)
        if payload:
            # kind of an awkward workaround for not using sessions
            user_search = client.query(kind=USERS)
            users = list(user_search.fetch())
            owner = None
            for user in users:
                if user['token'] == request.headers['Authorization'][7:]:
                    owner = user['sub']
            content = request.get_json()
            for each in content:
                if each not in ['name', 'theme']:
                    return ({"Error":"'name' and 'theme' are required. These two attributes are the only acceptable attributes to include in a request"}, 400)   
            new_library = datastore.entity.Entity(key=client.key(LIBRARIES))       
            try:
                new = {
                    "owner": owner, 
                    "name": content['name'], 
                    "theme": content['theme'],
                    "books": [],
                    } 
            except KeyError:
                return ({"Error":"You do not have permission to create a library"}, 403)
            new_library.update(new)
            client.put(new_library)
            new['id'] = new_library.key.id
            new['self'] = request.base_url + '/' + str(new_library.key.id)
            return (new, 201)
        else:
            return({"Error": "You do not have permission to create a library"}, 403)
    elif request.method == 'GET':
        the_libraries = []
        try:
            payload = check_jwt_first(request)
            print(payload)
        except AuthError: 
            return({"Error": "You do not have permission to view libraries"}, 401)
        query = client.query(kind=LIBRARIES)
        results = list(query.fetch())
        query_limit = 5
        if request.args.get('offset'):
            query_offset = int(request.args.get('offset'))
        else:
            query_offset = 0
        the_iterator = query.fetch(limit=query_limit, offset=query_offset)
        pages = the_iterator.pages
        results = list(next(pages))
        if the_iterator.next_page_token:
            next_offset = query_offset + query_limit
            next_url = request.base_url + "?limit=" + str(query_limit) + "&offset=" + str(next_offset)
        else: 
            next_url = None
        for e in results:
            if e['owner'] == payload['sub']: 
                e['id'] = e.key.id
                the_libraries.append(e)
        final = {
            "next": next_url,
            "libraries": the_libraries
        }
        return (final, 200)
        return (json.dumps(the_libraries), 200)


@app.route('/libraries/<library_id>', methods=['DELETE'])
def delete_library(library_id):
    if not library_id:
        return({"Error":"Deleting all objects is not allowed. Include a book_id in your request"}, 405)
    payload = check_jwt_first(request)
    library_key = client.key(LIBRARIES, int(library_id))
    library = client.get(key=library_key)
    if not library:
        return ({"Error": "No library with that library_id was found in the database. Check your library_id and try again"}, 404)
    if not payload or payload['sub'] != library['owner']:
        return ({"Error": "You do not have permission to delete this library"}, 403)
    for book in library['books']:
        book_key = client.key(BOOKS, int(book))
        update_book = client.get(key=book_key)
        print(type(library_id), update_book['library'])
        update_book['library'].remove(int(library_id))
        client.put(update_book)
        # update_book.remove(library_id)
    client.delete(library_key)
    return ('', 204)    


@app.route('/libraries/<library_id>', methods=['GET'])
def one_library(library_id):
    if 'application/json' not in request.accept_mimetypes: 
        return({"Error":  "Only JSON media can be requested"}, 406)
    payload = check_jwt_first(request)
    library_key = client.key(LIBRARIES, int(library_id))
    library = client.get(key=library_key)
    if not library:
        return ({"Error": "No library with that library_id was found in the database. Check your library_id and try again"}, 404)
    if not payload or payload['sub'] != library['owner']:
        return ({"Error": "You do not have permission to view this library"}, 403)
    return_lib = library
    titles = []
    for book in return_lib['books']:
        book_key = client.key(BOOKS, int(book))
        the_book = client.get(key=book_key) 
        titles.append(the_book['title'])
    return_lib["books"] = titles
    return_lib["self"] = request.base_url + "/libraries/" + library_id
    return_lib["id"] = library_id
    return (json.dumps(return_lib), 200)  


@app.route('/libraries/<library_id>/books/<book_id>', methods=['PUT'])
def add_one_book(library_id, book_id):
    payload = check_jwt_first(request)
    library_key = client.key(LIBRARIES, int(library_id))
    library = client.get(key=library_key)
    if not library:
        return ({"Error": "Invalid value for \'library\': library does not exist"}, 404)
    if not payload or payload['sub'] != library['owner']:
        return ({"Error": "You do not have permission to add a book to this library"}, 403)
    if int(book_id) in library['books']:
        return({"Error": "That book is already in the library"}, 400)
    book_key = client.key(BOOKS, int(book_id))
    book = client.get(key=book_key)
    if not book:
        return ({"Error": "Invalid value for \'books\': book does not exist"}, 404)
    lib_books = library['books']
    lib_books.append(book.key.id)
    book_libs = book['library']
    book_libs.append(library.key.id)
    library.update({"books":lib_books})
    client.put(library)
    book.update({"library":book_libs})
    book.update()
    client.put(book)
    library["id"] = library_id
    # library["self"] = request.base_url + "/libraries/" + library_id
    return(json.dumps(library), 200)


@app.route('/libraries/<library_id>/books/<book_id>', methods=['DELETE'])
def remove_one_book(library_id, book_id):
    payload = check_jwt_first(request)
    library_key = client.key(LIBRARIES, int(library_id))
    library = client.get(key=library_key)
    if not library:
        return ({"Error": "Invalid value for 'library': library does not exist"}, 404)
    if not payload or payload['sub'] != library['owner']:
        return ({"Error": "You do not have permission to remove a book from this library"}, 403)

    book_key = client.key(BOOKS, int(book_id))
    book = client.get(key=book_key)
    if not book:
        return ({"Error": "Invalid value for 'book': book does not exist"}, 404)
    if int(book_id) not in library['books']:
        return({"Error": "That book is not a part of the library"}, 400)
    lib_books = library['books']
    lib_books.remove(book.key.id) #check
    book_libs = book['library']
    book_libs.remove(library.key.id) #check
    library.update({"books":lib_books})
    client.put(library)
    book.update({"library":book_libs})
    book.update()
    client.put(book)
    return('', 204)


@app.route('/books/<book_id>', methods=['PATCH', 'PUT'])
def edit_book(book_id):
    if not book_id:
        return ({"Error": "Method not allowed - include a book id with your request"}, 405)       
    if not check_jwt_first(request):
        return ({"Error": "You do not have permission to edit a book"}, 403)  
    content = request.get_json()
    for key in content: 
       if key not in ["author", "title", "genre"]:
           return ({"Error": "'author', 'title', and 'genre' are required and are the only acceptable attributes"}, 400)
    book_key = client.key(BOOKS, int(book_id))
    book = client.get(key=book_key)
    if not book:
       return ({"Error": "No book with that book_id was found in the database. Check your book_id and try again"}, 404)
    if request.method == 'PATCH':
        for key in content: 
            book.update({key: content[key]})
    #PUT
    else:
        book.update({"title": content["title"], "author": content["author"], "genre": content["genre"]})
    client.put(book)
    book["id"] = book_id
    book["self"] = request.base_url + "/libraries/" + book_id
    return (json.dumps(book), 200)

   
@app.route('/libraries/<library_id>', methods=['PATCH', 'PUT'])
def edit_library(library_id): 
    if not library_id:
       return ({"Error": "Method not allowed - include a library id with your request"}, 405)      
    payload = check_jwt_first(request)
    content = request.get_json()
    for key in content: 
      if key not in ["name", "theme"]:
          return ({"Error": "'name' and 'theme' are the only acceptable attributes"}, 400)
    library_key = client.key(LIBRARIES, int(library_id))
    library = client.get(key=library_key)
    if not library:
      return ({"Error": "No library with that library_id was found in the database. Check your library_id and try again"}, 404)
    if not payload or payload['sub'] != library['owner']:
       return ({"Error": "You do not have permission to modify a library"}, 403) 
    if request.method == 'PATCH':
       for key in content: 
           library.update({key: content[key]})
    #PUT
    else:
       library.update({"name": content["name"], "theme": content["theme"]})
    client.put(library)
    library["id"] = library_id
    library["self"] = request.base_url + "/libraries/" + library_id
    return (json.dumps(library), 200)


#cleanup routes for testing
@app.route('/deleteallbooks', methods=['DELETE'])
def total_elimination_books():
    query = client.query(kind=BOOKS)
    results = list(query.fetch())
    for e in results:
        client.delete(e)
    return ('', 204)

@app.route('/deletealllibraries', methods=['DELETE'])
def total_elimination_libraries():
    query = client.query(kind=LIBRARIES)
    results = list(query.fetch())
    for e in results:
        client.delete(e)
    return ('', 204)

@app.route('/deleteallusers', methods=['DELETE'])
def total_elimination_users():
    query = client.query(kind=USERS)
    results = list(query.fetch())
    for e in results:
        client.delete(e)
    return ('', 204)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8083, debug=True)