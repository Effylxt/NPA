import threading
import time
import glob
import os
import shutil

from config import GlobalConfig


__all__ = [
    'startSpaceMonitor',
]


conf = GlobalConfig()

class SpaceMonitor:
    def __init__(self):
        self.max_space_in_bytes = conf.get('max_space_in_mb') * 1024L * 1024L
        self.max_keep_time_in_seconds = conf.get('max_keep_time_in_minute') * 60.0
        self.check_internal_in_second = conf.get('check_internal_in_second')
        
    def start(self):
        t = threading.Thread(target=self.monitor)
        self.monitor = t
        t.start()
        
    def monitor(self):
        print "Enter SpaceMonitor monitor thread"
        print "Start SpaceMonitor runner thread"
        
        while True:
            runner = threading.Thread(target=self.runner)
            runner.start()
            runner.join()
            print "SpaceMonitor runner thread died, restart thread again"
    
    def runner(self):
        # this is long long ago, so it would trigger
        # sweep the first time
        last_sweep_time = 0.0
        
        # Wait for other thread to be stabilized
        time.sleep(2)
        
        while True:
            # Do sweep first
            cur = time.time()
           
            if cur - last_sweep_time > self.check_internal_in_second:
                # wait long enough, do sweep job
                self.doSweep()

                # update recorded time
                last_sweep_time = cur
            else:
                # sleep for a while
                time.sleep(self.check_internal_in_second)
    
    @staticmethod
    def collectInfo(dir):
        # input dir name
        # output dict of
        #   dir
        #   size
        #   mtime       
            
        res = {}
        
        # dir
        res['dir'] = dir
        
        # mtime
        stat = os.stat(dir)
        res['mtime'] = stat.st_mtime
        
        # size
        fsize = 0;
        try:
            stat = os.stat(dir + "\\main.cap")
        except:
            pass
        else:
            fsize = stat.st_size
        res['size'] = fsize

        return res
        
    @staticmethod
    def compareItem(a, b):
        # sort according to 
        #   mtime: older < newer
        #   size: smaller < bigger
        mtimecmp = cmp(a['mtime'], b['mtime'])
        if mtimecmp != 0:
            return mtimecmp
        
        return cmp(a['size'], b['size'])
    
    def doSweep(self):
        # Find all dirs and collect information
        # 29f33cd3-c1a9-4d12-a336-0f6d76ca100e
        save_dir = conf.get('save_dir')
        pat = save_dir + "%s-%s-%s-%s-%s" % (
            '?' * 8, '?' * 4, '?' * 4, '?' * 4, '?' * 12)
        dirs = glob.glob(pat)
        
        infoList = map(self.collectInfo, dirs)
        
        # Sort according to deletion order
        infoList = sorted(infoList, self.compareItem)
        
        # Do deletion
        # Collect total size
        sizeTotal = 0L
        for item in infoList:
            sizeTotal += item['size']
        
        #print "Total size %d" % sizeTotal
        now = time.time()
        for item in infoList:
            # if item expires or size total is larger then config'ed
            # need to delete
            
            if ((now - item['mtime'] > self.max_keep_time_in_seconds)
                or (sizeTotal >= self.max_space_in_bytes)):
                #print "Delete %s" % item['dir']
                # delete it and update size
                shutil.rmtree(item['dir'])
                sizeTotal -= item['size']

theSpaceMonitor = None
            
def startSpaceMonitor():
    global theSpaceMonitor
    theSpaceMonitor = SpaceMonitor()
    theSpaceMonitor.start()
    
    
            