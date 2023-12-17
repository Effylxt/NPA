import copy
import re
from command import *

__all__ = [
    'GeneralAnalysis',
    'iSCSIAnalysis',
    'TCPAnalysis',
    'SMBAnalysis',
    'SMB2Analysis',
    'NFSV3Analysis',
    'NFSV4Analysis',
    'UDPAnalysis',
]

class BaseAnalysis:
    def __init__(self, env):
        self.env = env
        
    def analyze(self):
        result = dict()
        
        self.internal_analysis(result)
        
        self.result = copy.copy(result)
        
        return copy.copy(result)

    def get_analysis_result(self):
        return copy.copy(self.result)

class GeneralAnalysis(BaseAnalysis):
    def internal_analysis(self, result):
    
        # 1. capinfos
        params = {
            'filename' : self.env['filename']
        }
        value = CapInfos(params).execute()
        
        result['capinfos'] = value
        
        # 2. flow
        duration_text = value['Capture duration']
        
        match = re.match(r'(?P<t>\d+) seconds', duration_text)
        
        if match:
            duration = match.group('t')
            duration = float(duration) / 11.9875
            
            params = {
            'filename' : self.env['filename'],
            'duration' : duration
            }
            
            value = FlowInfo(params).execute()
            result['flowinfo'] = value  
        else:    
            result['flowinfo'] = None
        
        
        
        

class iSCSIAnalysis(BaseAnalysis):
    def internal_analysis(self, result):
    
        # 1. SRT
        params = {
            'filename' : self.env['filename']
        }
        
        value = iSCSISRTInfo(params).execute()
        
        result['srt'] = value

        # 2. IO Size
        # Read
        params = {
            'filename' : self.env['filename']
        }
        
        value = iSCSIReadSize(params).execute()
        
        result['read'] = value
        
        # Write
        params = {
            'filename' : self.env['filename']
        }
        
        value = iSCSIWriteSize(params).execute()
        
        result['write'] = value
        
    
class TCPAnalysis(BaseAnalysis):
    def internal_analysis(self, result):
        
        conn = self.env['conn']
        
        # 1. Retrans
        params = {
            'filename' : self.env['filename'],
            'src_ip' : self.env['conn']['src_ip'],
            'dest_ip' : self.env['conn']['dest_ip']
        }
        value = TCPRetrans(params).execute()
        
        result['retrans'] = value
        
        result['tframes'] = long(conn['tframes'])
        
        trate = float(value['tf']) / float(result['tframes'])
        value['trate_f'] = trate
        
        # convert to string with three digits after "."
        value['trate_s'] = "%.3f" % (trate * 100.0,)
       
        # 2. SACK
        params = {
            'filename' : self.env['filename']
        }
        value = TCPSACK(params).execute()
        
        result['sack'] = value
        
        
        # 3. TCP Zero Window 
        params = {
            'filename' : self.env['filename'],
            'src_ip' : self.env['conn']['src_ip'],
            'dest_ip' : self.env['conn']['dest_ip']
        }
        value = TCPZeroWin(params).execute()
        
        result['zerowin'] = value
        
        # 4. Delay ACK
        params = {
            'filename' : self.env['filename'],
            'src_ip' : self.env['conn']['src_ip'],
            'dest_ip' : self.env['conn']['dest_ip']
        }
        value = TCPDelayACK(params).execute()
        
        result['delayack'] = value
        
        # calculate factor
        value['delayack_waste'] = 0.2 * (
            value['sf_i'] + value['df_i']) 
        factor =  value['delayack_waste'] / conn['duration_f']

        value['delayack_factor'] = factor
        
class SMBAnalysis(BaseAnalysis):
    def internal_analysis(self, result):
    
        # 1. General SRT
        params = {
            'filename' : self.env['filename'],
        }
        value = SMBSRTInfo(params).execute()
        result['srt'] = value
        
        # 2. Read
        params = {
            'filename' : self.env['filename']
        }
        value = SMBReadSize(params).execute()
        
        result['read'] = value
        
        
        # 3. Write
        params = {
            'filename' : self.env['filename'],
        }
        value = SMBWriteSize(params).execute()
        
        result['write'] = value
    

class SMB2Analysis(BaseAnalysis):
    def internal_analysis(self, result):
        # 1. General 
        # Read SRT
        params = {
            'filename' : self.env['filename'],
        }
        value = SMB2ReadSRTInfo(params).execute()
        result['readsrt'] = value
    
        # Write SRT
        params = {
            'filename' : self.env['filename'],
        }
        value = SMB2WriteSRTInfo(params).execute()
        result['writesrt'] = value
    
        # 2. IO Size
        # Read
        params = {
            'filename' : self.env['filename'],
        }
        value = SMB2ReadSize(params).execute()
        result['read'] = value
        
        # Write
        params = {
            'filename' : self.env['filename'],
        }
        value = SMB2WriteSize(params).execute()
        result['write'] = value

class NFSV3Analysis(BaseAnalysis):
    def internal_analysis(self, result):
    
        # 1. General SRT
        params = {
            'filename' : self.env['filename'],
        }
        value = NFSV3SRTInfo(params).execute()
        result['srt'] = value
        
        # 2. Read
        params = {
            'filename' : self.env['filename']
        }
        value = NFSV3ReadSize(params).execute()
        
        result['read'] = value
        
        
        # 3. Write
        params = {
            'filename' : self.env['filename'],
        }
        value = NFSV3WriteSize(params).execute()
        
        result['write'] = value
        
class NFSV4Analysis(BaseAnalysis):
    def internal_analysis(self, result):
    
        # 1. SRT
        # Read SRT
        params = {
            'filename' : self.env['filename'],
        }
        value = NFSV4ReadSRTInfo(params).execute()
        result['readsrt'] = value
        
        # Read SRT
        params = {
            'filename' : self.env['filename'],
        }
        value = NFSV4WriteSRTInfo(params).execute()
        result['writesrt'] = value
        
        # 2. Read
        params = {
            'filename' : self.env['filename']
        }
        value = NFSV4ReadSize(params).execute()
        
        result['read'] = value
        
        
        # 3. Write
        params = {
            'filename' : self.env['filename'],
        }
        value = NFSV4WriteSize(params).execute()
        
        result['write'] = value        

class UDPAnalysis(BaseAnalysis):
    def internal_analysis(self, result):
    
        # TTL exceeded 
        params = {
            'filename' : self.env['filename'],
        }
        value = UDPTTLExceeded(params).execute()
        result['ttlexceeded'] = value
        
          