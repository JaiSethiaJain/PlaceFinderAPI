from flask import Flask ,  request, render_template, url_for, redirect , flash , jsonify 
from pymongo import MongoClient
import flask_login
import json
from bson import json_util
from passlib.hash import sha256_crypt
from wtforms import Form , BooleanField , PasswordField , TextField , validators
import requests
from os import urandom,remove
from binascii import hexlify
from bs4 import BeautifulSoup

MONGODB_URI = "***********************************************************"
client = MongoClient(MONGODB_URI)
db = client.get_database("*******")
users = db.registeredusers
history = db.browsehistory
rev = db.reviews

mykey = "**********************************************"
GOOGLE_PLACE_FINDER_API = "***********************************"

app = Flask(__name__)
app.secret_key = "******************************"

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
	d=users.find_one({"username":username})
	if d is None:
           return
	user = User()
	user.id = username
	return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    d=users.find_one({"username":username})
    if d is None:
        return
    user = User()
    user.id = username
    password=request.form.get('password')
    user.is_authenticated = sha256_crypt.verify(d['password'] , password)
    return user

class RegisterationForm(Form):
   username = TextField("Username" , [validators.Length(min = 4 , max = 20)])
   email = TextField("Email Address" , [validators.Length(min = 6 , max = 50)])
   password = PasswordField("Password" , [validators.Required() , validators.EqualTo("confirm" , message = "Password must match")])
   confirm = PasswordField("Repeat Password")
   accept_tos = BooleanField('i accept the terms of service and the privacy notice (last update 1/March/2018)' , [validators.Required()])


@app.route('/' , methods = ['GET' , 'POST'])
def home_page():
    if flask_login.current_user.is_authenticated:
        return redirect(url_for("dashboard" , user_id = flask_login.current_user.id))
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        place_photos = request.form.get('photos')
        #flash(place_photos)
        #print(place_photos)
        params = {}
        params['input'] = place_photos
        params['key'] = mykey
        resp = requests.get(GOOGLE_PLACE_FINDER_API , params = params)
        places = resp.json()
        predictions = places.get('predictions')
        place_elements = []
        for prediction in predictions:
            urltemp = "https://maps.googleapis.com/maps/api/place/details/json"
            place_id = prediction['place_id']
            partemp = {"key":mykey,
                       "placeid":place_id}
            rtemp = requests.get(urltemp , params = partemp)
            datatemp = rtemp.json()
            try:
                photos = datatemp.get('result').get('photos')[0].get('photo_reference')
            except:
                continue
            photourl = "https://maps.googleapis.com/maps/api/place/photo?maxheight=800&key="+mykey+"&photoreference="+photos
            #print(photourl)
            #flash(photourl)
            place_elements.append((photourl , prediction.get('description')))
        return render_template("photos.html" , place_elements=place_elements)
    return "ok"

@app.route('/login/' , methods = ['GET' , 'POST'])
def login_page():
    #if flask_login.current_user.is_authenticated:
    #    return redirect(url_for("dashboard" , user_id = flask_login.current_user.id))
    
    try:
        if request.method == "GET":
            return render_template("login.html")
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            #print(username , password)
            d = users.find_one({"username":username})


            #flash(username)
            #flash(password)
            if d is None:
                flash("invalid username")
                return redirect(url_for("login_page"))
            check_password = sha256_crypt.verify(password , d['password'])
            if check_password:
                user = User()
                user.id = username
                flask_login.login_user(user)
                return(redirect(url_for("protected")))

            else:
                error = " invalid credentials....try again "
                return redirect(url_for("login_page"))
    except Exception as e:
        flash("sorry for the inconvinience .....plzz try one more time")
        return redirect(url_for("login_page"))
    return "ok"

@app.route('/registeration/' , methods = ["GET" , "POST"])
def new_user():
   if flask_login.current_user.is_authenticated:
      return redirect(url_for("dashboard" , user_id = flask_login.current_user.id))
   try:
      form = RegisterationForm(request.form)

      if request.method == "GET":
         #print("step1")
         return render_template('registeration.html' , form = form)

      elif request.method == "POST" and form.validate():
         #print("step2")
         username = form.username.data
         #print(username)
         email = form.email.data
         password = sha256_crypt.encrypt((str(form.password.data)))
         first_name = request.form.get('firstname')
         last_name = request.form.get('lastname')
         country = request.form.get('country')
         #print("step3")
         try:
            if users.find_one({'username': username}):
               #print("stepfuck")
               flash("username already exist....choose another username")
               return redirect(url_for("new_user"))
            else:
               #print("step4")
               new_user = {}
               new_user['username']=username
               new_user['email']=email
               new_user['password']=password
               new_user['firstname'] = first_name
               new_user['lastname'] = last_name
               new_user['country'] = country
               new_user['key'] = hexlify(urandom(24)).decode('utf-8')
               #print("step5")
               users.insert_one(new_user)
               #print("step6")
               flash("registeration completed .....now login to access your api")
               #print("step7")
               return redirect(url_for("login_page"))
         except Exception as e:
            flash("some thing wrong happened......plzz try one more time")
            return redirect(url_for("new_user"))
      else:
          flash("try again.....some data is wrong")
          return redirect(url_for("new_user"))
   
   except Exception as e:
      flash("some thing wrong happened......plzz try one more time")
      return redirect(url_for("new_user"))
   return "ok"

@app.route('/dashboard/<user_id>/' , methods = ["GET" , "POST"])
@flask_login.login_required
def dashboard(user_id):
    if request.method == "GET":
        placehistory = []
        user = users.find_one({"username":user_id})
        xyz = history.find({"username":user_id})
        #print(xyz)
        if xyz:
            for abc in xyz:
                #print(abc)
                placehistory.append(abc['searchplace'])
        else:
            placehistory = None
            
        return render_template("profile.html" , username = user.get('username') , firstname = user.get('firstname') , lastname = user.get('lastname') ,
                               country = user.get('country') , apikey = user.get('key') , email = user.get('email') , placehistory = placehistory)
    elif request.method == "POST":
        searchplace = request.form.get('searchplace')

        return redirect(url_for("placeinfo" , user_id = user_id , searchplace = searchplace))
        
        #print(place_elements , datas)
        
    return "ok"

@app.route('/dashboard/<user_id>/<searchplace>' , methods = ['GET' , 'POST'])
@flask_login.login_required
def placeinfo(user_id , searchplace):
    if request.method == "GET":

        h = history.find_one({"username":user_id , "searchplace":searchplace})
        if h is None:
        
            # wiki pedia scraping

            wiki1 = searchplace.replace(" " , "_")
            wiki2 = "https://en.wikipedia.org/wiki/"+wiki1
            r = requests.get(wiki2)
            soup = BeautifulSoup(r.content , "html5lib")
            table = soup.find("tbody")
            trs = table.findAll("tr")
            datas = []
            for tr in trs:
                try:
                    data = []
                    th = tr.find("th")
                    #print(th.text)
                    td = tr.find("td")
                    #print(td.text)
                    data.append(th.text)
                    data.append(td.text)
                    datas.append(data)
                except:
                    continue

                
            # place photos
            
            params = {}
            params['input'] = searchplace
            params['key'] = mykey
            resp = requests.get(GOOGLE_PLACE_FINDER_API , params = params)
            places = resp.json()
            predictions = places.get('predictions')
            place_elements = []
            for prediction in predictions:
                urltemp = "https://maps.googleapis.com/maps/api/place/details/json"
                place_id = prediction['place_id']
                partemp = {"key":mykey,
                           "placeid":place_id}
                rtemp = requests.get(urltemp , params = partemp)
                datatemp = rtemp.json()
                try:
                    photos = datatemp.get('result').get('photos')[0].get('photo_reference')
                except:
                    continue
                photourl = "https://maps.googleapis.com/maps/api/place/photo?maxheight=800&key="+mykey+"&photoreference="+photos

                place_elements.append((photourl , prediction.get('description')))

            his = {}
            his["username"] = user_id
            his["searchplace"] = searchplace
            his["datas"] = datas
            his["place_elements"] = place_elements
            history.insert_one(his)

            return render_template("wikisearch.html" , username = user_id , datas = datas , place_elements = place_elements , review = None)


        else:
            datas = h["datas"]
            place_elements = h["place_elements"]
            r = rev.find_one({"username":user_id , "searchplace":searchplace})
            #print(r , "hello")
            if r:
                return render_template("wikisearch.html" , username = user_id , searchplace = searchplace , datas = datas , place_elements = place_elements , review = r.get("review"))
            else:
                return render_template("wikisearch.html" , username = user_id , searchplace = searchplace , datas = datas , place_elements = place_elements , review = None)

        
    if request.method == "POST":
        review = request.form.get("review")
        #print(review)
        if review:
            a = {}
            a["username"] = user_id
            a["searchplace"] = searchplace
            a["review"] = review
            rev.insert_one(a)
        searchplace = request.form.get("searchplace")
        if searchplace:
            return redirect(url_for("placeinfo" , user_id = user_id , searchplace = searchplace))
        
        return redirect(url_for("dashboard" , user_id = user_id))

    return "ok"


@app.route('/dashboard/<user_id>/<searchplace>/edit' , methods = ['GET' , 'POST'])
@flask_login.login_required
def editreview(user_id , searchplace):
    if request.method == "GET":
        r = rev.find_one({"username":user_id , "searchplace":searchplace})
        return render_template("editreview.html" , username = user_id , review = r.get("review"))
    if request.method == "POST":
        
        review = request.form.get("review")
        if review:
            a = {}
            a["review"] = review
            rev.update_one({"username":user_id,"searchplace":searchplace},{"$set":a})

        return redirect(url_for("dashboard" , user_id = user_id))
    
@app.route('/dashboard/<user_id>/<searchplace>/delete/' , methods = ['GET'])
@flask_login.login_required
def deleteplace(user_id , searchplace):
    if request.method == "GET":
        history.delete_one({"username":user_id , "searchplace":searchplace})
        rev.delete_one({"username":user_id , "searchplace":searchplace})
        return redirect(url_for("dashboard" , user_id = user_id))
    
    return "ok"


@app.route("/api",methods=['GET','POST','PATCH','DELETE'])
def api():
    if (request.method=='GET'):
        key=request.args.get("key")
        if key is None:
            return jsonify({"error":"Key is required. Read the docs"}),404
        d=users.find_one({"key":key})
        if d is None:
             return jsonify({"error":"You are not registered."}),404
        username=d['username']
        place=request.args.get("searchplace")
        if place is None:
            searchplaces = list(history.find({"username":username}))
            for searchplace in searchplaces:
                review  = rev.find_one({"username":username , "searchplace":searchplace.get("searchplace")})
                if review and review.get("review"):
                    searchplace["review"] = review.get("review")
                searchplace.pop('_id')
            return json_util.dumps(searchplaces) , 200
        searchplace = history.find_one({"username":username , "searchplace":place})
        if searchplace is None:
            return jsonify({"error":"no place with given name"})
        review  = rev.find_one({"username":username , "searchplace":searchplace.get("searchplace")})
        
        if review and review.get("review"):
            searchplace["review"] = review.get("review")

        searchplace.pop("_id")
        
        return json_util.dumps(searchplace) , 200
            
    key=request.form.get("key")
    if key is None:
        return jsonify({"error":"Key is required. Read the docs"}),400
    d=users.find_one({"key":key})
    if d is None:
        return jsonify({"error":"You are not registered."}),400
    username=d['username']
    if request.method=='POST':
        searchplace=request.form.get("searchplace")
        if searchplace is None:
            return jsonify({"error":"place name required whose data you want"}),400
        
        existingplace=history.find_one({"username":username,"searchplace":searchplace})
        if existingplace is not None:
            return jsonify({"error":"place already exists in history"}),400
        
        review=request.form.get("review")
        
        # wiki pedia scraping

        wiki1 = searchplace.replace(" " , "_")
        wiki2 = "https://en.wikipedia.org/wiki/"+wiki1
        r = requests.get(wiki2)
        soup = BeautifulSoup(r.content , "html5lib")
        table = soup.find("tbody")
        trs = table.findAll("tr")
        datas = []
        for tr in trs:
            try:
                data = []
                th = tr.find("th")
                #print(th.text)
                td = tr.find("td")
                #print(td.text)
                data.append(th.text)
                data.append(td.text)
                datas.append(data)
            except:
                continue

            
        # place photos
        
        params = {}
        params['input'] = searchplace
        params['key'] = mykey
        resp = requests.get(GOOGLE_PLACE_FINDER_API , params = params)
        places = resp.json()
        predictions = places.get('predictions')
        place_elements = []
        for prediction in predictions:
            urltemp = "https://maps.googleapis.com/maps/api/place/details/json"
            place_id = prediction['place_id']
            partemp = {"key":mykey,
                       "placeid":place_id}
            rtemp = requests.get(urltemp , params = partemp)
            datatemp = rtemp.json()
            try:
                photos = datatemp.get('result').get('photos')[0].get('photo_reference')
            except:
                continue
            photourl = "https://maps.googleapis.com/maps/api/place/photo?maxheight=800&key="+mykey+"&photoreference="+photos

            place_elements.append((photourl , prediction.get('description')))

        his = {}
        his["username"] = username
        his["searchplace"] = searchplace
        his["datas"] = datas
        his["place_elements"] = place_elements
        history.insert_one(his)
        if review:
            a = {}
            a["username"] = username
            a["searchplace"]=searchplace
            a["review"] = review
            rev.insert_one(a)
        his["review"] = review
        return json_util.dumps(his),200
    elif request.method=='PATCH':
        placereview=request.form.get("searchplace")
        if placereview is None:
            return jsonify({"error":"name of place is required for updation. Read the docs."}),400
        newreview = request.form.get("review")
        if newreview is None:
            return jsonify({"error":"write the note/review for the place"}) , 400
        review = rev.find_one({"username":username , "searchplace":placereview})
        place = history.find_one({"username":username , "searchplace":placereview})
        if place is None:
            return jsonify({"error" : "no details found for given place name"}),400
        if review:
            a = {}
            a["review"] = newreview
            rev.update_one({"username":username,"searchplace":placereview},{"$set":a})
        else:
            a = {}
            a["username"] = username
            a["searchplace"]=placereview
            a["review"] = newreview
            rev.insert_one(a)
            
            a.pop("_id")
        return json_util.dumps(a) , 200

    elif request.method=='DELETE':
        searchplace=request.form.get("searchplace")
        if searchplace is None:
            return jsonify({"error":"name of the place is required for deletion. Read the docs"}),400
        history.delete_one({"username":username,"searchplace":searchplace})
        rev.delete_one({"username":username,"searchplace":searchplace})
        return jsonify({"result":"Successfully deleted."}),200



@app.route('/protected')
@flask_login.login_required
def protected():
    flash("You are logged in as :"+flask_login.current_user.id)
    return redirect(url_for("dashboard" , user_id = flask_login.current_user.id))

@app.route('/logout')
@flask_login.login_required
def logout():
    flask_login.logout_user()
    flash("you are successfully logged out")
    return redirect(url_for("home_page"))

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'


@app.route('/contactus/')
def contact_us():
    if flask_login.current_user.is_authenticated:
        return redirect(url_for("dashboard" , user_id = flask_login.current_user.id))

    return render_template("contactus.html")

@app.route('/aboutapi/')
def about_API():
    if flask_login.current_user.is_authenticated:
        d=users.find_one({"username":str(flask_login.current_user.id)})
        return render_template("apidoclogin.html",key=d['key'],username=d['username'])
    return render_template("apidoc.html")

@app.errorhandler(404)
def page_not_found(e):
   return render_template("404.html")

@app.errorhandler(405)
def page_not_found(e):
   return render_template("405.html")




if __name__ == '__main__':
   app.run(port=8000, debug=True, use_reloader=True)
