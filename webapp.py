from flask import Flask, request, redirect, url_for, render_template, abort, jsonify, Response
import os
import json
import glob
import cPickle

from uuid import uuid4

from config import GlobalConfig

from command import *
from analysis import *
from task import *

conf = GlobalConfig()
app = Flask(__name__)

@app.route("/favicon.ico")
def favicon():
    return redirect(url_for("static", filename='img/favicon.ico'))

@app.route("/")
def index():

    title = 'Index'
    
    return render_template("index.html", title=title, isIndex=True)
    
@app.route("/upload", methods=["POST"])
def upload():
    """Handle the upload of a file."""
    form = request.form

    # Is the upload using Ajax, or a direct POST by the form?
    is_ajax = False
    if form.get("__ajax", None) == "true":
        is_ajax = True

    # Target folder for these uploads.
    target = conf.get('save_dir')
    
    if not os.path.exists(target):
        try:
            os.mkdir(target)
        except:
            if is_ajax:
                return ajax_response(False, "Couldn't create upload directory")
            else:
                return "Couldn't create upload directory"
    
    upload_key = str(uuid4())
    
    target += upload_key
    try:
        os.mkdir(target)
    except:
        if is_ajax:
            return ajax_response(False, "Couldn't create upload directory: /Capture/{}".format(upload_key))
        else:
            return "Couldn't create upload directory: /Capture/{}".format(upload_key)

    for upload in request.files.getlist("file"):
        filename = upload.filename.rsplit("/")[0]
        destination = target + "\\main.cap"
        upload.save(destination)
    if is_ajax:
        return ajax_response(True, upload_key)
    else:
        return redirect(url_for("capture_status", uuid=upload_key))

'''
Dir layout
    main.cap
        primary data file
    main.bin
        parsed connection list, last should be OK
    <index>.cap
        filtered file
    <index>.bin
    
    conns: 
        'global_filename': global cap
        'conn_list': list of connections
        'conn' : current connection
        
'''
@app.route("/capture/<uuid>")
def select_connection(uuid):

    # Check whether dir exists. If not, create it
    save_dir = conf.get('save_dir')
    main_cap = save_dir + uuid + "\\main.cap"

    if not os.path.exists(main_cap):
        abort(404)
    main_bin_file = save_dir + uuid + "\\main.bin"
    
    conns = None
    
    key = TaskExtractCapture.make_key(uuid)

    task_result = get_task_manager().query_task(key)

    if task_result and task_result['status'] == OK:
        #has the result, so render the page with connection list

        f = open(main_bin_file, "rb")
        try:
            conns = cPickle.load(f)
        except:
            f.close()

        title = 'Select Connection'
        
        return render_template("conn_table.html",
            isIndex=False,
            wait=False,
            uuid=uuid,
            conns=conns['conn_list'],
            title=title)
        
    else:
        # Post a new task to execute asynchronously
        task = TaskExtractCapture(uuid)
        
        get_task_manager().post_task(task)
        
        # Render page as Analyzing
        title = 'Analyzing Connection ...'
        
        return render_template("conn_table.html",
            isIndex=False,
            wait=True,
            uuid=uuid,
            title=title)
            
def ajax_response(status, msg):
    status_code = "ok" if status else "error"
    return json.dumps(dict(
        status=status_code,
        msg=msg,
    ))
    
@app.route("/connection/<uuid>/<int:index>")
def analyze_connection(uuid, index):

    save_dir = conf.get('save_dir')
    
    # General file names
    main_cap = save_dir + uuid + "\\main.cap"
    main_bin_file = save_dir + uuid + "\\main.bin"
    conns_single_cap = save_dir + uuid + "\\" + str(index) + ".cap"
    conns_single_bin = save_dir + uuid + "\\" + str(index) + ".bin"
    conns_single_done = save_dir + uuid + "\\" + str(index) + ".done"
    
    # Not found
    if not os.path.exists(main_cap):
        abort(404)
    
     # load connections
    conns = None
    if not os.path.exists(main_bin_file):
        # at this point, we should have already generate this file
        # otherwise it is error
        abort(404)
    else:
        f = open(main_bin_file, "rb")
        try:
            conns = cPickle.load(f)
        except:
            f.close()
    
    # check index out of bound
    if index >= len(conns['conn_list']):
        abort(404)
    
    conn = conns['conn_list'][index]
        
    key = TaskAnalyzeConnection.make_key(uuid, index)

    task_result = get_task_manager().query_task(key)

    if task_result and task_result['status'] == OK:
        #has the result, so render the page with connection list
        result = dict()
        f = open(conns_single_bin, "rb")
        try:
            result = cPickle.load(f)
        except:
            f.close()
            
        return render_template(
            'show_connection.html', 
            wait = False, 
            **result)
        
    else:
        # Post a new task to execute asynchronously
        task = TaskAnalyzeConnection(uuid, index)
        get_task_manager().post_task(task)
        
        # Render page as waiting
        title = 'Analyzing Connection ...'
        
        return render_template(
            'show_connection.html', 
            wait=True,
            title=title,
            uuid=uuid,
            index=index)
        
@app.route("/data/<uuid>/<int:index>")
def generate_data(uuid, index):

    save_dir = conf.get('save_dir')
    
    # General file names
    main_cap = save_dir + uuid + "\\main.cap"
    main_bin_file = save_dir + uuid + "\\main.bin"
    conns_single_cap = save_dir + uuid + "\\" + str(index) + ".cap"
    conns_single_bin = save_dir + uuid + "\\" + str(index) + ".bin"
    
    # Not found
    if not os.path.exists(main_cap):
        abort(404)
    
    # load connections
    conns = None
    if not os.path.exists(main_bin_file):
        # at this point, we should have already generate this file
        # otherwise it is error
        abort(404)
    else:
        f = open(main_bin_file, "rb")
        try:
            conns = cPickle.load(f)
        except:
            f.close()
            
    # check index out of bound
    if index >= len(conns['conn_list']):
        abort(404)
    
    conn = conns['conn_list'][index]
    
    result = dict()
   
    
    if os.path.exists(conns_single_bin):
        f = open(conns_single_bin, "rb")
        try:
            result = cPickle.load(f)
        except:
            f.close()
            
    # generate
    # { ticks: <label>,
    #   data: data_array }
    
    data = dict()
    flowinfo = result['general']['flowinfo']
    ticklist = list()
    datalist = list()
    
    for item in flowinfo:
        label = "%.2f -> %.2f" %(float(item['start']), float(item['end']))
        b = long(item['frames'])
        ticklist.append(label)
        datalist.append(b)
        
    data['ticks'] = ticklist 
    data['data'] = datalist
    
    return jsonify(data)
    
    
@app.route("/api/capture/<uuid>")
def capture_status(uuid):   
    
    save_dir = conf.get('save_dir')
    main_cap = save_dir + uuid + "\\main.cap"
    
    if not os.path.exists(main_cap):
        abort(404)
    
    key = TaskExtractCapture.make_key(uuid)
    
    task_result = get_task_manager().query_task(key)
    
    return jsonify(task_result)
    
@app.route("/api/connection/<uuid>/<int:index>")    
def caconnection_status(uuid, index):   
    
    key = TaskAnalyzeConnection.make_key(uuid, index)
    
    task_result = get_task_manager().query_task(key)
    
    return jsonify(task_result)
    
@app.route("/notice")    
def notice():   
    
    title = "Notice"
    return render_template(
        'notice.html',
        title=title)
    