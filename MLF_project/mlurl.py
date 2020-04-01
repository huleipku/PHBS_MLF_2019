'''
    File name: mlurl.py
    Python Version: 3.6
'''

import os
import numpy as np
import shutil
import re
import math
import numpy
import pandas as pd
import csv
import math
import string
import sys
import fileinput
import json
import urllib
import urllib3
import requests
import zipfile
import time
import argparse
import pickle
from termcolor import colored, cprint
import colorama
import webbrowser
import base64
import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.utils import shuffle
import sklearn.ensemble as ske
from sklearn.preprocessing import StandardScaler
from sklearn import model_selection
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, confusion_matrix
from sklearn.metrics import f1_score
from sklearn.model_selection import cross_val_predict, learning_curve
from sklearn.metrics import roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns
# Class Entropy to calculate URL entropy.
# Entropy is often described as a measure of randomness. Malicious URLs 
# will typically have a higher entropy and randomness.
# Entropy is calculated using Shannon Entropy -


class Entropy():
    def __init__(self, data):
        self.data = data

    def range_bytes(): return range(256)

    def range_printable(): return (ord(c) for c in string.printable)

    def H(self, data, iterator=range_bytes):
        if not data:
            return 0
        entropy = 0
        for x in iterator():
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

# Class URLFeatures extracts specific features from URLs.
class URLFeatures():
    # Bag Of Words method is used for text analysis.
    # Here URLs are described by word occurrences while completely 
    # ignoring the relative position information of the words in 
    # the document.
    def bag_of_words(self, url):
        vectorizer = CountVectorizer()
        content = re.split('\W+', url)
        X = vectorizer.fit_transform(content)
        num_sample, num_features = X.shape
        return num_features
    
    # Contains IP method to check the occurence of an IP
    # address within a URL.
    def contains_IP(self, url):
        check = url.split('/')
        reg = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
        result = 0
        for item in check:
            if re.search(reg, item):
                result = 1
        return result
    
    # URL Length method to calculate the URL length.
    # Malicious URLs can often be very long in comparrison to
    # benign URLs.
    def url_length(self, url):
        return len(url)

    # Special Characters method to check for specific special 
    # chars. Sometimes Malicious URLs contain a higher number of
    # special characters.
    # In this method, a counter is used to count the number of 
    # special characters that are found within a URL.
    def special_chars(self, url):
        counter = 0
        if '*' in url:
            counter += 1
        if ';' in url:
            counter += 1
        if '%' in url:
            counter += 1
        if '!' in url:
            counter += 1
        if '&' in url:
            counter += 1
        if ':' in url:
            counter += 1

        return counter

    # Suspicious Strings method to check for suspicious strings within
    # the URLs. A higher number of suspicious strings would indicate a 
    # possibly malicious URL. 
    def suspicious_strings(self, url):
        counter = 0
        
        # Malicious URLs may contain the string '.exe' in reference to
        # downloading a possibly malicious executable.
        if '.exe' in url:
            counter += 1
        # Malicious URLs may use base64 encoding to encode and 
        # possibly obfuscate information.
        if 'base64' in url:
            counter += 1
        # The occurence of '/../' may possibly indicate file
        # file inclusion.
        if '/../' in url:
            counter += 1
        if '.pdf' in url:
            counter += 1

        # Phishing can use social engineering to lure victims to
        # click on malicious links. The use of the word free may
        # be included within URLs to trick users in visiting 
        # malicious websites.
        if 'free' in url:
            counter += 1
        if 'Free' in url:
            counter += 1
        if 'FREE' in url:
            counter += 1

        # .onion and .tor references the use of tor. Such domains
        # are suspicious and according to RFC 7686 should be kept
        # off public internet.
        if '.onion' in url:
            counter += 1
        if '.tor' in url:
            counter += 1
        # Suspicious domains.
        if '.top' in url:
            counter += 1
        if '.bid' in url:
            counter += 1
        if '.ml' in url:
            counter += 1
        # Bitcoin references.
        if 'bitcoin' in url:
            counter += 1
        if '.bit' in url:
            counter += 1
        if '.php?email=' in url:
            counter += 1
        # Possible command execution.
        if 'cmd=' in url:
            counter += 1

        return counter

    # Number Of Digits method returns the number of digits
    # contained within a URL. Malicious URLs often have higher
    # entropy and can contain lots of numbers.
    def num_digits(self, url):
        numbers = sum(i.isdigit() for i in url)
        return numbers

    # Popularity method checks the url popularity
    # against the top 1 million urls contained within the
    # umbrella dataset.
    # Sites contained within this dataset are not malicious.
    def popularity(self, url):
        result = 0
        domain = url.split('/', 1)[-1]

        with open('benign_urls/top1m_rank.csv', 'rt') as f:
            reader = csv.reader(f, delimiter='|')
            for row in reader:
                if domain == row[1]:
                    result = row[0]
                    
        return int(result)


# Class safebrowse integrates the Google Safebrowse API to check if Google
# classes the URLs as safe. Any URLs classed as not safe may be malicious.
# Although blacklists and resources such as Google safebrowsing cannot predict
# malicious URLs, the appearance of a URL in these lists is a powerful feature. 


class SafeBrowse():
    def __init__(self, apikey):
        self.safe_base = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s' % (apikey)
        self.platform_types = ['ANY_PLATFORM']
        self.threat_types = ['THREAT_TYPE_UNSPECIFIED',
                             'MALWARE', 
                             'SOCIAL_ENGINEERING', 
                             'UNWANTED_SOFTWARE', 
                             'POTENTIALLY_HARMFUL_APPLICATION']
        self.threat_entry_types = ['URL']

    def set_threat_types(self, threats):

        self.threat_types = threats

    def set_platform_types(self, platforms): 
        
        self.platform_types = platforms

    def threat_matches_find(self, *urls): 
        try:
            threat_entries = []
            results = {}

            for url_ in urls: 
                url = {'url': url_} 
                threat_entries.append(url)

            request_body = {
                'client': {
                    'clientId': 'MLURL_CLIENT',
                    'clientVersion': '1.0'
                },
                'threatInfo': {
                    'threatTypes': self.threat_types,
                    'platformTypes': self.platform_types,
                    'threatEntryTypes': self.threat_entry_types,
                    'threatEntries': threat_entries
                }
            }
            
            headers = {'Content-Type': 'application/json'}
            r = requests.post(self.safe_base, 
                            data=json.dumps(request_body), 
                            headers=headers, timeout=2)

            jdata = r.json()
            #print(jdata['matches'][0]['threatEntryType'])
            
            # If the threatEntryType matches the string URL, the parsed URL
            # has been classified as not safe by Google. In this case a 1
            # is returned and otherwise a 0 is returned.
            if jdata['matches'][0]['threatEntryType'] == 'URL':
                return 1
            else:
                return 0
        except:
            return 0 

# Extract features function extracts all features from URLs and stores it in a
# feature list. This list can then be returned and writen to a csv file.
def extract_features(url):
    features = []
    
    # Parses input URL to remove http:// or https://.
    # The umbrella dataset does not contain this and thus,
    # is not required for certain feature extractions.
    parsed_url = parse_url(url)
    
    # Appends URL to features list.
    features.append(url)

    # Retrieve URL entropy and append to feature list.
    getEntropy = Entropy(parsed_url)
    entropy = getEntropy.H(parsed_url)
    features.append(entropy)

    # Creates feature object of class URL features.
    feature = URLFeatures()

    # Append Bag Of Words to feature list.  
    features.append(feature.bag_of_words(parsed_url))
    
    # Append Contains IP address to feature list.
    features.append(feature.contains_IP(parsed_url))

    # Append URL length to feature list.
    features.append(feature.url_length(parsed_url))

    # Append amount of special characters to feature list.
    features.append(feature.special_chars(parsed_url))

    # Append number of suspicious strings to feature list.
    features.append(feature.suspicious_strings(url))

    # Append number of digits within the URL to feature list.
    features.append(feature.num_digits(parsed_url))

    # Append site popularity to feature list.
    features.append(feature.popularity(parsed_url))

    # Appends Google Safebrowsing verdict to features list.
    apikey = base64.b64decode('QUl6YVN5Qzl0c3gzcFlmQXhPN25PSGE5UWtNdjR6VW1QNk90UmQw')
    apikey = apikey.decode('utf-8')
    safe = SafeBrowse(apikey)
    response = safe.threat_matches_find(url) 
    features.append(response)

    # Returns extracted features from features list.
    return features

# Parse URL function strips http:// and https:// from
# URLs. Umbrella dataset does not contain this and thus,
# is not required for certain feature extractions.
def parse_url(url):

    if 'http://' in url:
        url_http = url.split('http://', 1)[-1]
        return url_http
    elif 'https://' in url:
        url_https = url.split('https://', 1)[-1]
        return url_https
    else:
        return url

# Create dataset function creates a CSV file and writes all the URL
# features to it.
def create_dataset():
    output_file = "data_urls.csv"
    csv_delimeter = '|'
    csv_columns = [
        "URL",
        "Entropy",
        "BagOfWords",
        "ContainsIP",
        "LengthURL",
        "SpecialChars",
        "SuspiciousStrings",
        "NumberOfDigits",
        "Popularity",
        "Safebrowsing",
        "Malicious", 
    ]

    # Opens file that features will be written to for reading.
    feature_file = open(output_file, 'a')
    
    # Writes the feature column names to csv file. 
    feature_file.write(csv_delimeter.join(csv_columns) + "\n")

    # Opens the malicious URLs file for reading and creates a list
    # that contains all the rows (URLs) from the file.
    with open('malicious_urls/malicious_urls.csv', 'r') as f:
        reader = csv.DictReader(f, delimiter='\n')
        rows = list(reader)

    # For every row or URL in the malicious URL file, extract all
    # the features.
    for row in rows:
        print('\n[+] Extracting features from ', row['URL'])
        try:
            e = extract_features(row['URL'])

            # Appends a binary value of 1 to the feature file to represent
            # a malicious URL label.
            e.append(1)

            # Writes features to feature file.
            feature_file.write(csv_delimeter.join(map(lambda x: str(x), e)) + "\n")
            print(colored('\n[*] ', 'green') + "Features extracted successfully.\n")
        except:
            print("[-] Error: Unable to extract features.\n")
    
    # The above is then repeated below for the benign URLs.

    with open('benign_urls/benign_urls.csv', 'r') as f:
        reader = csv.DictReader(f, delimiter=',')
        rows = list(reader)

    for row in rows:
        print('\n[+] Extracting features from ', row['URL'])
        try:
            e = extract_features(row['URL'])
            e.append(0)
            feature_file.write(csv_delimeter.join(map(lambda x: str(x), e)) + "\n")
            print(colored('\n[*] ', 'green') + "Features extracted successfully.\n")
        except:
            print("[-] Error: Unable to extract features.\n")

    feature_file.close()

# Train model function trains a classifier
# on the URL dataset and saves the configuration in the form of
# a pickle file.
def train_model():
    # Creates a pandas dataframe and reads in the URL dataset with
    # extracted features. 
    df = pd.read_csv('data_urls.csv', sep='|')

    # Assigns X to features. Drops URL name and label.
    X = df.drop(['URL', 'Malicious'], axis=1).values
    
    # Assigns y to labels.
    y = df['Malicious'].values

    # Split data into training and test datasets.
    X_train, X_test, y_train, y_test = model_selection.train_test_split(X, y, test_size=0.2, random_state=42) 

    # Print the number of training and testing samples.
    print("\t Training samples: ", len(X_train))
    print("\t Testing samples: ", len(X_test))
    
    #s = StandardScaler()
    #X_train_scale = s.fit_transform(X_train)
    #X_test_scale = s.fit_transform(X_test)

    # Train Random forest algorithm on training dataset.
    # I have try some other algorithms we learned in class,like svm or lr
    # however,the learning curve is not acceptable for us
    # so i choose to use the RandomForest here,which works better.
    clf = ske.RandomForestClassifier(n_estimators=50)   
    clf.fit(X_train, y_train)

    # Perform cross validation and print out accuracy.
    score = model_selection.cross_val_score(clf, X_test, y_test, cv=10)
    print("\n\t Cross Validation Score: ", round(score.mean()*100, 2), '%')

    # Calculate f1 score.
    y_train_pred = cross_val_predict(clf, X_train, y_train, cv=3)
    f = f1_score(y_train, y_train_pred)
    print("\t F1 Score: ", round(f*100, 2), '%')

    #plot_ROC_CURVE(y_train, y_train_pred)

     # plot the matrix
    '''
    cm=confusion_matrix(y_train,y_train_pred)
    plot_confusion_matrix(cm,["malicious","benign"],"Confusion Matrix")
    plt.show()
    '''
    # plot learning curve
    #get_learning_curve(X_train,y_train)
    # Save the configuration of the classifier and features as a pickle file.

    all_features = X.shape[1]
    features = []

    for feature in range(all_features):
        features.append(df.columns[1+feature])

    try:
        print("\n Saving algorithm and feature list in classifier directory...")
        joblib.dump(clf, 'classifier/classifier.pkl')
        open('classifier/features.pkl', 'wb').write(pickle.dumps(features))
        print(colored('\n[*] ', 'green') + " Saved.")
    except:
        print('\n Error: Algorithm and feature list not saved correctly.\n')


def get_learning_curve(X, y):
    clf=ske.RandomForestClassifier(n_estimators=50)
    parameter_grid = np.array([200, 500, 800, 1100])
    train_size, train_scores, validation_scores = learning_curve(clf, X, y, train_sizes=parameter_grid, cv=5)


    # 把数据画成图像
    plt.figure(figsize=(10, 8), dpi=80)
    plt.plot(parameter_grid, 100 * np.average(train_scores, axis=1), color='black')
    plt.title('Learning curve')
    plt.xlabel('Number of training samples')
    plt.ylabel('Accuracy')
    plt.show()

def plot_confusion_matrix(cm, labels_name, title):
    cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]    # 归一化
    plt.imshow(cm, interpolation='nearest')    # 在特定的窗口上显示图像
    plt.title(title)    # 图像标题
    plt.colorbar()
    num_local = np.array(range(len(labels_name)))
    plt.xticks(num_local, labels_name, rotation=90)    # 将标签印在x轴坐标上
    plt.yticks(num_local, labels_name)    # 将标签印在y轴坐标上
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
def plot_ROC_CURVE(y,Y):
    # plot ROC curve
    fpr, tpr, threshold = roc_curve(y, Y)  ###计算真正率和假正率
    roc_auc = auc(fpr, tpr)  ###计算auc的值

    plt.figure()
    lw = 2
    plt.figure(figsize=(10, 10))
    plt.plot(fpr, tpr, color='darkorange',
             lw=lw, label='ROC curve (area = %0.2f)' % roc_auc)  ###假正率为横坐标，真正率为纵坐标做曲线
    plt.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver operating characteristic example')
    plt.legend(loc="lower right")
    plt.show()
# Get URL information function extracts features from a user supplied
# URL. The function extracts all features similarly to extract_features()
# but instead saves the extracted features in the form of a dictionary. 
def get_url_info(url):
    # Creates a dictionary for features to be stored in.
    features = {}
    
    # Parses input URL to remove http:// or https://.
    # The umbrella dataset does not contain this and thus,
    # is not required for certain feature extractions.
    parsed_url = parse_url(url)

    # Retrieve URL entropy and store in dictionary.
    getEntropy = Entropy(parsed_url)
    entropy = getEntropy.H(parsed_url)
    features['Entropy'] = entropy

    feature = URLFeatures()

    # Store Bag Of Words in dictionary.  
    features['BagOfWords'] = feature.bag_of_words(parsed_url)
    
    # Store Contains IP address in dictionary.
    features['ContainsIP'] = feature.contains_IP(parsed_url)

    # Store URL length in dictionary.
    features['LengthURL'] = feature.url_length(parsed_url)

    # Store amount of special characters in dictionary.
    features['SpecialChars'] = feature.special_chars(parsed_url)

    # Store amount of suspicious strings in dictionary.
    features['SuspiciousStrings'] = feature.suspicious_strings(url)

    # Store number of digits within the URL in dictionary.
    features['NumberOfDigits'] = feature.num_digits(parsed_url)

    # Store site popularity in dictionary.
    features['Popularity'] = feature.popularity(parsed_url)

    # Store Google Safebrowsing verdict in dictionary.
    apikey = base64.b64decode('QUl6YVN5QV9XbU53MHRyZTEybWtMOE1qYUExY0c3Smd4SnRuU0lv')
    apikey = apikey.decode('utf-8')
    safe = SafeBrowse(apikey)
    features['Safebrowsing'] = safe.threat_matches_find(url) 

    # Return features dictionary.
    return features

# Classify URL function passes in the input URL and classifies
# it as malicious or benign. 
def classify_url(url):

    # Loads classifier and feature configurations.
    clf = joblib.load(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'classifier/classifier.pkl'))

    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'rb').read())
    
    # Extracts features from input URL.
    data = get_url_info(url)
    feature_list = list(map(lambda x:data[x], features))

    # Classifies input URL as malicious or benign.
    result = clf.predict([feature_list])[0]

    if result == 0:
        print("MLURL has classified URL %s as " % url + colored("benign", 'green') + '.')
    else: 
        print("MLURL has classified URL %s as " % url + colored("malicious", 'red') + '.')
    
    return result


# Check valid URL function checks whether or not the input
# URL to classify is in a valid format.

def check_valid_url(url):
    print("\n[+] Validating URL format...")
    reg = re.compile('^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$')
    
    if re.match(reg, str(url)):
        print("URL is valid.")
    else:
        print("Error: URL is not valid. Please input a valid URL format. ")
        sys.exit(0)

def main():
    # Creates a command line parser.
    parser = argparse.ArgumentParser(epilog='MLURL uses machine learning to detect malicious URLs.',
    description="Machine Learning malicious URL classifier (MLURL)")
    parser.add_argument('-c', '--classify', dest='classify', help='Classify a new URL as malicious or benign.')    
    parser.add_argument('-g', '--generate_data', nargs='*', help='Generate the URL dataset.')
    parser.add_argument('-t', '--train', nargs='*', help='Train Random Forest Algorithm.')

    args = parser.parse_args()
    colorama.init()

    
    # Generates URL dataset.
    if args.generate_data is not None:
        print("\n[+] Generating URL data...")
        try:
            print("\n[+] Beginning feature extraction...")
            if os.path.exists('data_urls.csv'):
                os.remove('data_urls.csv')
                create_dataset()
            else:
                create_dataset()
            (colored("\n[*] ", 'green') + "Feature extraction successful.\n")
        except:
            print(colored("\n[-] ", 'red') + "Error: Feature extraction unsuccessful.\n")
    
    # Trains algorithm on URL dataset.
    if args.train is not None:
        print('\n  Training Random Forest model...\n')
        try:    
            train_model()
            print("Model successfully trained.")
        except:
            print("Error: Model unsuccessfully trained .")
    
    # Classifies input URL and checks using Virus Total API.

    if args.classify:
        print('\n Running Classifier...')
        check_valid_url(args.classify)
        classify_url(args.classify)

        
if __name__ == '__main__':
    main()
