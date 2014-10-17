import datetime
import netifaces
import json
import sys
import os.path
import glob

from multiprocessing import Process, Value
from multiprocessing.queues import Queue
from flask import Flask, render_template, request, Response, url_for, redirect

import leakdetector as ld

app = Flask(__name__)
app.config.update(dict(
    session = False,
    ld_out = Queue()
)) 
        
def ld_run(q, iface, outfile):
    while not q.empty(): q.get() # Flush queue

    outfile = os.path.join(os.getcwd(), "static", "traces", outfile)
    ld.run.main(iface, outfile=outfile, stdout=q)
    
def analyze_run(fn):
    infile = os.path.join(os.getcwd(), "static", "traces", fn)
    outfile = os.path.join(os.getcwd(), "static", "analysis", "analyzed-%s" % fn)
    ld.analyze.main(infile, outfile, True)

@app.route('/')
def home():
    defaultname = "trace-"+str(datetime.datetime.now()).replace(" ", "_")
    return render_template("record.html", defaultnm=defaultname, interfaces=netifaces.interfaces())
    
@app.route('/record', methods=['POST']) 
def record():
    action = request.form['action']
    
    if action == "start":
        
        if not app.config['session']:
            iface, fn = request.form['interface'], request.form['fn']
            print "Starting leak detector on %s, recording to %s." % ( iface, fn )
            
            app.config['session'] = Process(target=ld_run, args=(app.config['ld_out'], iface, fn))
            app.config['session'].start()
            
            return action
        else:
            return "ERR A session has already been started."
            
    elif action == "stop":
        if app.config['session']:            
            resp = {'action': action, 'info': 'Recorded 0 packets on en1.'}
            app.config['session'].terminate()
            app.config['session'] = False   
            return Response(json.dumps(resp), mimetype='text/json')
        else:
            return "ERR Leak detector is not currently running."
            
    else:
        return "ERR Invalid action."
        
@app.route('/proc-status')
def status():
    if app.config['ld_out'].empty():
        resp = {'stdout': False}
    else:
        lines = []
        while not app.config['ld_out'].empty():
            line = app.config['ld_out'].get()
            if line: lines.append(line)
        resp = {'stdout': lines}
        
    return Response(json.dumps(resp), mimetype='text/json')

@app.route('/list')    
def listfiles():
    traces = {
        'raw': map(os.path.basename, glob.glob('static/traces/*.json')),
        'processed': map(os.path.basename, glob.glob('static/analysis/*.json'))
    }
    return render_template('analyze.html', traces=traces)
        
@app.route('/analyze/<fn>')
def analyze(fn):
    outfn = os.path.join(os.getcwd(), "static", "analysis", "analyzed-%s"%fn)
    if not os.path.exists(outfn):
        analyze_run(fn)
    return redirect(url_for('display', fn="analyzed-%s"%fn))
        
@app.route('/display/<fn>')
def display(fn):
    return "Displaying %s" % fn
    
if __name__ == '__main__':
    app.run(debug=True)    