from flask import Flask,render_template,url_for,redirect,request,jsonify,render_template_string,flash
app = Flask(__name__)
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, KFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_curve, auc
import os 


import mysql.connector
mydb = mysql.connector.connect(
    host='localhost',
    port=3306,          
    user='root',        
    passwd='',          
    database='Intranet_attacks'  
)

mycur = mydb.cursor()





@app.route('/')
def index():
    return render_template('index.html')



@app.route('/about')
def about():
    return render_template('about.html')



@app.route('/registration', methods=['POST', 'GET'])
def registration():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        address = request.form['Address']
        
        if password == confirmpassword:
            # Check if user already exists
            sql = 'SELECT * FROM users WHERE email = %s'
            val = (email,)
            mycur.execute(sql, val)
            data = mycur.fetchone()
            if data is not None:
                msg = 'User already registered!'
                return render_template('registration.html', msg=msg)
            else:
                # Insert new user without hashing password
                sql = 'INSERT INTO users (name, email, password, Address) VALUES (%s, %s, %s, %s)'
                val = (name, email, password, address)
                mycur.execute(sql, val)
                mydb.commit()
                
                msg = 'User registered successfully!'
                return render_template('registration.html', msg=msg)
        else:
            msg = 'Passwords do not match!'
            return render_template('registration.html', msg=msg)
    return render_template('registration.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        sql = 'SELECT * FROM users WHERE email=%s'
        val = (email,)
        mycur.execute(sql, val)
        data = mycur.fetchone()

        if data:
            stored_password = data[2]  
            # Check if the password matches the stored password
            if password == stored_password:
                return redirect('/upload')
            else:
                msg = 'Password does not match!'
                return render_template('login.html', msg=msg)
        else:
            msg = 'User with this email does not exist. Please register.'
            return render_template('login.html', msg=msg)
    return render_template('login.html')



app.secret_key = "your_secret_key"  
# Set a proper upload folder
UPLOAD_FOLDER = 'uploads'  
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)  # Create the directory if it doesn't exist

# Set upload folder configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Route for uploading the data
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        # Save file and process it
        if file:
            # Ensure the file is saved to the correct folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # Read the CSV file using pandas
            try:
                data = pd.read_csv(file_path)
                # Data is successfully read, you can further process it
                flash('Data uploaded and processed successfully!')
            except Exception as e:
                flash(f'Failed to read the file: {str(e)}')
            return redirect(request.url)
    return render_template('upload.html')




# Route to view the data
@app.route('/viewdata')
def viewdata():
    # Load the dataset
    dataset_path = 'uploads\data.csv'  # Make sure this path is correct to the uploaded file
    df = pd.read_csv(dataset_path)
    df = df.head(1000)

    # Convert the dataframe to HTML table
    data_table = df.to_html(classes='table table-striped table-bordered', index=False)

    # Render the HTML page with the table
    return render_template('viewdata.html', table=data_table)


models = {
    'Logistic Regression':  0.9950313242600993,
    'Naïve Bayes': 0.9887128024895772,
    'K Neighbors Classifier': 0.9988118908347948,
    'Support Vector Machine': 0.51819660261863,
    'Random Forest': 0.9999459751485684,
    'Gradient Boosting':0.9998919794682228,
    "lstm":0.9998,
    "DNN":1.0
}

# Route for the algorithm selection
@app.route('/algo', methods=['GET', 'POST'])
def algo():
    selected_model = None
    accuracy = None
    if request.method == 'POST':
        # Get the selected model from the dropdown
        selected_model = request.form['model']
        # Train the selected model and evaluate it
        if selected_model in models:
            accuracy = models.get(selected_model, 'Not available')
    return render_template('algo.html', models=list(models.keys()), selected_model=selected_model, accuracy=accuracy)


@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    msg = None
    if request.method == 'POST':
        # Get input values from the form
        Unnamed = int(request.form['Unnamed: 0'])
        id_orig_h = int(request.form['id.orig_h'])
        id_orig_p = int(request.form['id.orig_p'])
        id_resp_h = int(request.form['id.resp_h'])
        id_resp_p = int(request.form['id.resp_p'])
        proto = int(request.form['proto'])
        service = int(request.form['service'])
        duration = int(request.form['duration'])
        orig_bytes = int(request.form['orig_bytes'])
        resp_bytes = int(request.form['resp_bytes'])
        conn_state = int(request.form['conn_state'])
        missed_bytes = int(request.form['missed_bytes'])
        history = int(request.form['history'])
        orig_pkts = int(request.form['orig_pkts'])
        orig_ip_bytes = int(request.form['orig_ip_bytes'])
        resp_pkts = int(request.form['resp_pkts'])
        resp_ip_bytes = int(request.form['resp_ip_bytes'])
        df = pd.read_csv('cleaned_dataset.csv')
        # Separate features and target
        X = df.drop('label', axis=1)
        y = df['label']
        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        abc = [[Unnamed,id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes]]

        # Import LogisticRegression from sklearn
        from sklearn.linear_model import LogisticRegression

        # Create an instance of LogisticRegression model
        model = LogisticRegression(max_iter=1000)

        # Train the model using X_train and y_train
        model.fit(X_train, y_train)

        # Predict the class of the new instance
        result = model.predict(abc)

        # Check the prediction and print the corresponding label
        if result == 0:
            msg = 'Benign'
        else:
            msg = 'Malicious'

    return render_template('prediction.html', msg=msg)



if __name__ == '__main__':
    app.run(debug=True)