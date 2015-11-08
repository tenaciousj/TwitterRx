#!/usr/bin/env python
# coding=utf-8
from flask import Flask, render_template, redirect, flash, request
from flask_bootstrap import Bootstrap

from json import loads

import logging, urllib3, urllib, urlparse
import oauth2, hmac
import pprint
import requests

from base64 import b64encode

from flask.ext.wtf import Form
from wtforms import StringField
from wtforms.validators import DataRequired, Length

from hashlib import sha1
from random import random
from time import time

app = Flask(__name__)
app.secret_key = "tdKfy8fVvAQHQtIVgjQnU4kTPpqsuNTivXySnKIIW7Ka8"
Bootstrap(app)

APP_TOKEN = {}

AUTHORIZATION_CODE_ENDPOINT='EXAMPLE'
MANAGER = urllib3.PoolManager()

CONSUMER_KEY = '7s49w03C9RtaMkSAzQqxO3NPK'
CONSUMER_SECRET = 'EcDfgTjRowsBIoXlerkE1oYaoVrKR60UySDhxicZ8Bjfk4k6pn'
CONSUMER = oauth2.Consumer(CONSUMER_KEY, CONSUMER_SECRET)

REQUEST_TOKEN={}
ACCESS_TOKEN={}


# class TweetForm(Form):
#     tweet = StringField('tweet', validators=[DataRequired(),Length(max=140)])

def get_oauth_header(method,url,status):
    parameters = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_nonce":  sha1(str(random)).hexdigest(),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time())),
        "oauth_token": ACCESS_TOKEN['oauth_token'],
        "oauth_version": "1.0",
        "status": status
    }

    """ Build the string that forms the base of the signature """
    base_string = "%s&%s&%s" % (method,urllib.quote(url,""),urllib.quote('&'.join(sorted("%s=%s" % (key,value)
                                                                                         for key,value in parameters.iteritems())),""))

    """ Create signature using signing key composed of consumer secret and token secret obtained during 3-legged dance"""
    signature = hmac.new("%s&%s" % (urllib.quote(CONSUMER_SECRET,""),urllib.quote(ACCESS_TOKEN['oauth_token_secret'],"")),
                         base_string,sha1)

    """ Add result to parameters and output is format required for header """
    parameters['oauth_signature'] = signature.digest().encode("base64").rstrip('\n')
    return 'OAuth %s' % ', '.join(sorted('%s="%s"' % (urllib.quote(key,""),urllib.quote(value,""))
                for key,value in parameters.iteritems() if key != 'status'))

def get_request_token():
    global REQUEST_TOKEN
    resp, content = oauth2.Client(CONSUMER).request('https://api.twitter.com/oauth/request_token', "GET")

    if resp['status'] != '200':
        print content
        raise Exception("Invalid response %s." % resp['status'])

    REQUEST_TOKEN = dict(urlparse.parse_qsl(content))
    return "%s?oauth_token=%s" % ('https://api.twitter.com/oauth/authorize', REQUEST_TOKEN['oauth_token'])

def get_app_token():
    try:
        app_token = MANAGER.urlopen('POST',
                                    'https://api.twitter.com/oauth2/token',
                                    headers={
                                        'Authorization': "Basic %s" % b64encode("%s:%s" % (CONSUMER_KEY,CONSUMER_SECRET)),
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                    },
                                    body="grant_type=client_credentials")
        return loads(app_token.data)
    except: raise

# @app.route("/tweet/<screen_name>", methods=['GET', 'POST'])
# def dm_user(screen_name):
#     if 'oauth_token' not in ACCESS_TOKEN:
#         return redirect(get_request_token())

#     else:
#         """ Authorized so render template ready for message sending """
#         form = TweetForm()
#         if form.validate_on_submit():
#             payload = "status=%s" % urllib.quote(form.tweet.data)

#             auth_header = get_oauth_header('POST','https://api.twitter.com/1.1/statuses/update.json',urllib.quote(form.tweet.data))
#             logging.log(logging.DEBUG,auth_header)

#             """ Now send the tweet.... """
#             try: response = MANAGER.urlopen("POST", 'https://api.twitter.com/1.1/statuses/update.json',
#                                             headers={"Authorization": auth_header, 'Content-Type': 'application/x-www-form-urlencoded'},
#                                             body=payload)
#             except: raise

#             flash("Tweet sent mentioning @%s" % screen_name) if response.status == 200 else flash("Error sending tweet: %s" % response.data)
#             return redirect("/")

#         return render_template('tweet.html', title="Send Tweet", form=form, message="Hello world @%s" % screen_name)

@app.route("/")
def handle_root():
    return render_template('index.html')


@app.route("/gettweets",methods=["POST"])
def handle_gettweets():
    try:
        url="https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name="+request.form["twitterHandle"]

        user_timeline = MANAGER.urlopen('GET',
                                        url,
                                        headers={'Authorization': 'Bearer %s' % APP_TOKEN['access_token']})
        raw_tweets = loads(user_timeline.data)
        tweets = []
        #tweet_words = []

        #sanitize tweet to get rid of unnecessary words
        for item in raw_tweets:
            #tweet = item['text']
            tweets.append(str(item['text'].encode('utf-8')))
            # tweet_w = tweet.split(" ")
            # for w in tweet_w:
            #     if "#" in w:
            #         w = w.replace("#", "")
            #     if "http" not in w and "https" not in w and "@" not in w and "\U0" not in w and "\u" not in w:
            #         tweet_words.append(w.encode('utf-8'))

        #print tweet_strs
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(tweets)
        print "SENTIMENT ANALYSIS"
        answer = sentiment_analysis(tweets)
        print answer
        #return render_template('timeline.html',tweets=tweets)
        return render_template('timeline.html')
    except: raise

def sentiment_analysis(tweets):
    pos = 0
    neut = 0
    neg = 0
    for t in tweets:
        url = "http://text-processing.com/api/sentiment/"
        payload = { 'text': t }
        headers = {}
        r=requests.post(url, data=payload, headers=headers)

        j = r.json()
        if str(j['label']) == "pos":
            pos+=1
        elif str(j['label']) == "neutral":
            neut+=1
        else:
            neg+=1
    if pos >= neut and pos >= neg:
        return 1
    elif neut >= pos and neut >= neg:
        return 0
    else:
        return -1

@app.route("/callback")
def handle_callback():
    global ACCESS_TOKEN

    token = oauth2.Token(REQUEST_TOKEN['oauth_token'], REQUEST_TOKEN['oauth_token_secret'])
    token.set_verifier(request.args.get('oauth_verifier'))
    client = oauth2.Client(CONSUMER, token)

    resp, content = client.request('https://api.twitter.com/oauth/access_token', "POST")
    ACCESS_TOKEN = dict(urlparse.parse_qsl(content))

    """ User now logged in so just redirect to the DM page """
    return redirect("/")

if __name__ == "__main__":
    try:
        APP_TOKEN = get_app_token()
        APP_TOKEN['access_token']
    except: raise

    #app.run(port=8002, debug=True)
    app.run()
