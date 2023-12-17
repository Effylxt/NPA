import threading
import re

import cPickle
import copy
import time
import os.path

from uuid import uuid4

from config import GlobalConfig
from analysis import *
from command import *

__all__ = [
    'OK',
    'RUNNING',
    'NOT_FOUND',
    'TaskExtractCapture',
    'TaskAnalyzeConnection',
    'get_task_manager'
 
]

conf = GlobalConfig()
  
OK = 'ok'
RUNNING = 'running'
NOT_FOUND = 'not_found'
FAILED = 'failed'
task_manager = None

def get_task_manager():
    global task_manager
    return task_manager


class TaskManager:
    def __init__(self):
        self.task_lock = threading.RLock()
        # task_list and matcher must be 
        # accessed under lock
        self.task_list = []
        self.task_matcher = []
        
    def post_task(self, task):
        with self.task_lock:
            task_key = task.get_key()
            task_status = self.query_task(task_key)
            # insert only if it is not found
            if task_status['status'] == NOT_FOUND:
                self.task_list.append(task)
        
        return task_key
        
    def query_task(self, task_key):    
        result = None
        with self.task_lock:
            # find in list
            for task in self.task_list:
                if task.get_key() == task_key:
                    # found it
                    result = task.get_status()    
                    break
            else:
                #not found in list, look in directory
                for tm in self.task_matcher:
                    result = tm(task_key)
                    if result:
                        break
                else:
                    # not found in list, not found by matcher
                    result = {
                        'status' : NOT_FOUND,
                        'message' : ["Can't find task"],
                        'progress' : 0
                        }
        return result            
                
    def register_matcher(self, method):
        with self.task_lock:
            self.task_matcher.append(method)
    
    def get_lock(self):
        return self.task_lock
        
    def monitor(self):
        print "Enter monitor thread"
        print "Start runner thread"
        while True:
            runner = threading.Thread(target=self.runner)
            runner.start()
            runner.join()
            print "Runner thread died, restart thread again"
        
    def runner(self):
        while True:
            task = None
            with self.task_lock:
                if len(self.task_list) > 0:
                    task = self.task_list[0]
            
            if task:
                # run task and remove self
                task.run()
                with self.task_lock:
                    del(self.task_list[0])
            else:
                # Nothing to do so sleep 1 s
                time.sleep(1)
                
                
    def start(self):
        t = threading.Thread(target=self.monitor)
        self.monitor = t
        t.start()
        
        
task_manager = TaskManager()
        
class TaskBase:
    def __init__(self):
        # cached_status must be accessed 
        # under TaskManager's lock in normal case
        self.cached_status = {
            'status' : RUNNING,
            'message' : [],
            'progress' : 0
            }
        self.running = False
    def post(self):
        get_task_manager().post_task(self)
    
    def run(self):
        
        if self.running:
            # if we enter here it is likely that
            # the runner thread hit a problem and 
            # exit. This task has been scheduled again.
            # so skip it before we figure out how to handle
            # it.
            return
            
        self.running = True
        
        self.run_internal()
        
    def get_key(self):
        raise Exception("Need to implement this")
        
    def get_status(self):
        raise Exception("Need to implement this")
        
    def get_status(self):
        result =  None
        with get_task_manager().get_lock():
            result = copy.deepcopy(self.cached_status)
        
        return result
        
    def put_status(self, status):
        with get_task_manager().get_lock():
            self.cached_status = copy.deepcopy(status)
        pass
        
class TaskExtractCapture(TaskBase):
    def __init__(self, uuid):
        TaskBase.__init__(self)
        self.uuid = uuid
        
    def run_internal(self):
        task_manager = get_task_manager()
        
        uuid = self.uuid
        
        status = None

        # Check whether dir exists. If not, create it
        save_dir = conf.get('save_dir')
    
        main_cap = save_dir + uuid + "\\main.cap"
    
        if not os.path.exists(main_cap):
            status = {
                'status' : FAILED,
                'message' : [],
                'progress' : 0
            }
            
            self.put_status(status)
            # no more to do, bail out
            return
        
        main_bin_file = save_dir + uuid + "\\main.bin"
        main_done_file = save_dir + uuid + "\\main.done" 
    
        conns = None
    
        if os.path.exists(main_bin_file):
            # already has the bin file
            # make sure done file exists, then bail out
            f = open(main_done_file, "wb")
            f.close()
            
            status = {
                'status' : OK,
                'message' : [],
                'progress' : 100
            }
            
            self.put_status(status)
            return
            
        # generate connection list
        params = {
            'filename' : main_cap
        }
        
        conns = dict()
        
        conn_list = list();
        
        status = {
                'status' : RUNNING,
                'message' : ["Extract TCP connections"],
                'progress' : 10
            }
        self.put_status(status)
        
        tcps = GetAllTCPConns(params).execute()
        conn_list.extend(tcps)
        
        status['message'].append("Extract UDP connections")
        status['progress'] = 50
        self.put_status(status)
        udps = GetAllUDPConns(params).execute()
        conn_list.extend(udps)
        
        conns['conn_list'] = conn_list
        
        status['message'].append("Save Analysis Result")
        status['progress'] = 90
        self.put_status(status)        
        
        f = open(main_bin_file, "wb")
        try:
            cPickle.dump(conns, f)
        except:
            f.close()
            
        status['message'].append("Save Analysis Result")
        status['progress'] = 95
        self.put_status(status)

        # write done file
        f = open(main_done_file, "wb")
        f.close()
        
        status['message'].append("Save log")
        status['progress'] = 100
        self.put_status(status)
            
    def get_key(self):
        return "TaskExtractCapture/%s" % (self.uuid,)
        
    @staticmethod
    def make_key(uuid):
        return "TaskExtractCapture/%s" % (uuid,)
    
    @staticmethod
    def matcher(key):
        found = None
        uuid = None
        pat = re.compile('TaskExtractCapture/(?P<uuid>[\w-]{36})')
        m = pat.match(key)
        if not m:
            return None
        else:
            d = m.groupdict()
            uuid = d['uuid']
        
        # Now look for done file
        conf = GlobalConfig()
        
        save_dir = conf.get('save_dir')

        # General file names
        main_done_file = save_dir + uuid + "\\main.done"
        
        # Find done file under lock
        with get_task_manager().get_lock():
            if os.path.exists(main_done_file):
                found = {
                    'status' : OK,
                    'message' : [],
                    'progress' : 100
                    }
        return found
        
    
class TaskAnalyzeConnection(TaskBase):
    def __init__(self, uuid, index):
        TaskBase.__init__(self)
        self.uuid = uuid
        self.index = index
        
    def run_internal(self):
        
        task_manager = get_task_manager()
        
        uuid = self.uuid
        index = self.index

        save_dir = conf.get('save_dir')
    
        # General file names
        main_cap = save_dir + uuid + "\\main.cap"
        main_bin_file = save_dir + uuid + "\\main.bin"
        conns_single_cap = save_dir + uuid + "\\" + str(index) + ".cap"
        conns_single_bin = save_dir + uuid + "\\" + str(index) + ".bin"
        conns_single_done = save_dir + uuid + "\\" + str(index) + ".done"
    
        # Not found
        if not os.path.exists(main_cap):
            status = {
                'status' : FAILED,
                'message' : [],
                'progress' : 0
            }
            
            self.put_status(status)
            # no more to do, bail out
            return
    
        status = {
                'status' : RUNNING,
                'message' : ["Load all connections"],
                'progress' : 5
            }
        self.put_status(status)
        
        # load connections
        conns = None
        if not os.path.exists(main_bin_file):
            # at this point, we should have already generate this file
            # otherwise it is error
            status = {
                'status' : FAILED,
                'message' : [],
                'progress' : 0
            }
            
            self.put_status(status)
            # no more to do, bail out
            return
        else:
            f = open(main_bin_file, "rb")
            try:
                conns = cPickle.load(f)
            except:
                f.close()
    
        status['message'].append("Load single connection")
        status['progress'] = 10
        self.put_status(status)
                
        # check index out of bound
        if index >= len(conns['conn_list']):
            status = {
                'status' : FAILED,
                'message' : [],
                'progress' : 0
            }
            
            self.put_status(status)
            # no more to do, bail out
            return
    
        conn = conns['conn_list'][index]
        
        # filter single connection if not exists
        if not os.path.exists(conns_single_cap):
            if conn['type'] == 'TCP':
                klass = FilterTCPConn
            else:
                klass = FilterUDPConn
            params = dict(conn)
            params['filename'] = main_cap
            params['outfilename'] = conns_single_cap

            klass(params).execute()
            
        # Now begin to analyze singe connection
        # Note: All ports are in string
        
        # Compose Env
        result = dict()

        #env = dict(conns)
        env = dict()
        env['conn'] = conn
        env['index'] = index
        env['filename'] = conns_single_cap

        result.update(env)
        result['uuid'] = uuid
        
        status['message'].append("Begin analysis")
        status['progress'] = 30
        self.put_status(status)
        # Layout of result
        # <dict>[analysis_typename] for each
        if (conn['src_port'] == '3260' or conn['dest_port'] == '3260'):
            # iSCSI
            result['show_type'] = 'iscsi' 
            
            result['general'] = GeneralAnalysis(env).analyze()
            result['iscsi'] = iSCSIAnalysis(env).analyze()
            result['tcp'] = TCPAnalysis(env).analyze()
            result['title'] = 'iSCSI' 
        
        elif (conn['src_port'] == '139' or conn['dest_port'] == '139' or conn['src_port'] == '445' or conn['dest_port'] == '445'):

            params = {
                'filename' : env['filename'],
            }
            
            check_smb = SMBType(params).execute()
            
            if check_smb[0]['smbf'] != '0':
                # is SMB
                result['show_type'] = 'smb' 
            
                result['general'] = GeneralAnalysis(env).analyze()
                result['smb'] = SMBAnalysis(env).analyze()
                result['tcp'] = TCPAnalysis(env).analyze()
                
                result['title'] = 'SMB' 

            else:
                # is SMB2
                result['show_type'] = 'smb2'
            
                result['general'] = GeneralAnalysis(env).analyze()
                result['smb2'] = SMB2Analysis(env).analyze()
                result['tcp'] = TCPAnalysis(env).analyze()
                
                result['title'] = 'SMB2' 
                
        elif (conn['src_port'] == '2049' or conn['dest_port'] == '2049'):
            params = {
                'filename' : env['filename'],
            }
            
            check_nfs = NFSType(params).execute()
            
            if check_nfs[0]['nfsv3f'] != '0':
                # is NFSV3
                result['show_type'] = 'nfsv3'
            
                result['general'] = GeneralAnalysis(env).analyze()
                result['nfsv3'] = NFSV3Analysis(env).analyze()
                
                if result['conn']['type'] == 'TCP':
                    result['tcp'] = TCPAnalysis(env).analyze()
                else:
                    result['udp'] = UDPAnalysis(env).analyze()
                    
                result['title'] = 'NFS v3'     
                
            else:
                # is NFSV4
                result['show_type'] = 'nfsv4'
            
                result['general'] = GeneralAnalysis(env).analyze()
                result['nfsv4'] = NFSV4Analysis(env).analyze()
                if result['conn']['type'] == 'TCP':
                    result['tcp'] = TCPAnalysis(env).analyze()
                else:
                    result['udp'] = UDPAnalysis(env).analyze()
                
                result['title'] = 'NFS v4'     
        else:
            result['general'] = GeneralAnalysis(env).analyze()
                
            if result['conn']['type'] == 'TCP':
                result['show_type'] = 'general_tcp'
                result['tcp'] = TCPAnalysis(env).analyze()
                
                result['title'] = 'TCP General'     
            else:
                result['udp'] = UDPAnalysis(env).analyze()
                result['show_type'] = 'general_udp'
                result['title'] = 'UDP General'     
        
        f = open(conns_single_bin, "wb")
        try:
            cPickle.dump(result, f)
        except:
            f.close()     
        
        # write done file of connection           
        f = open(conns_single_done, "wb")
        f.close()
        
        status['message'].append("Save log")
        status['progress'] = 100
        self.put_status(status)
        
    def get_key(self):
        return "TaskAnalyzeConnection/%s/%d" % (self.uuid, self.index)     

    @staticmethod
    def make_key(uuid, index):
        return "TaskAnalyzeConnection/%s/%d" % (uuid, index)     
    
    @staticmethod    
    def matcher(key):
        found = None
        uuid = None
        index = -1
        pat = re.compile('TaskAnalyzeConnection/(?P<uuid>[\w-]{36})/(?P<index>\d+)')
        m = pat.match(key)
        if not m:
            return None
        else:
            d = m.groupdict()
            uuid = d['uuid']
            index = int(d['index'])
            
        # Now look for done file
        conf = GlobalConfig()
        
        save_dir = conf.get('save_dir')

        # General file names
        conn_done_file = "%s%s\\%d.done" % (save_dir, uuid, index)
        
        # Find done file under lock
        if os.path.exists(conn_done_file):
            found = {
                'status' : OK,
                'message' : [],
                'progress' : 100
                }
        return found        

get_task_manager().register_matcher(TaskExtractCapture.matcher)
get_task_manager().register_matcher(TaskAnalyzeConnection.matcher)


    