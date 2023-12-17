from config import GlobalConfig
from subprocess import *
import re
import copy

__all__ = [
    'GetAllTCPConns',
    'GetAllUDPConns',
    'FilterTCPConn',
    'FilterUDPConn',
    'CapInfos',
    'FlowInfo',
    'iSCSISRTInfo',
    'iSCSIReadSize',
    'iSCSIWriteSize',
    'TCPRetrans',
    'TCPSACK',
    'TCPZeroWin',
    'TCPDelayACK',
    'UDPTTLExceeded',
    'SMBSRTInfo',
    'SMBReadSize',
    'SMBWriteSize',
    'SMB2ReadSRTInfo',
    'SMB2WriteSRTInfo',
    'SMB2ReadSize',
    'SMB2WriteSize',
    'NFSV3SRTInfo',
    'NFSV3ReadSize',
    'NFSV3WriteSize',
    'NFSV4ReadSRTInfo',
    'NFSV4WriteSRTInfo',
    'NFSV4ReadSize',
    'NFSV4WriteSize',
    'SMBType',
    'NFSType',
]

#sub class needs to provide
# compose_command(self)
# parse_command(self)
class BaseCommand:
    def __init__(self, params):
        self.config = GlobalConfig()
        self.params = params
        self.command = self.compose_command()
        self.raw_output = None
        self.parsed_output = dict()
        
    def execute(self):
        # execute
        # print "### Execute %s in class %s" % (self.command, self.__class__.__name__)
        (raw_output, e) = Popen(self.command , stdout=PIPE, stderr=PIPE).communicate()
        self.raw_output = raw_output
        # print "### Raw output %s" % raw_output
        self.parsed_output = self.parse_command()
        # print "### Raw output Done"
        return copy.copy(self.parsed_output)
        
    def get_command(self):
        return self.command
        
    def get_raw_output(self):
        return self.raw_output
    
    def get_parsed_output(self):
        return copy.copy(self.parsed_output)
        

# Input parameters: filename        
class GetAllTCPConns(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"conv,tcp\"".format(**newdict)
        
        return cmd
    
    def parse_command(self):
        pat = re.compile(("(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s*<->\s*"
            "(?P<dest_ip>[\d\.]+):(?P<dest_port>\d+)\s+(?P<dframes>\d+)\s+"
            "(?P<dbytes>\d+)\s+(?P<uframes>\d+)\s+(?P<ubytes>\d+)\s+"
            "(?P<tframes>\d+)\s+(?P<tbytes>\d+)\s+(?P<start>[\d\.]+)\s+(?P<duration>[\d\.]+)"))
            
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            match = pat.match(line)
            if match:
                d = match.groupdict()
                d['type'] = 'TCP'
                d['duration_f'] = float(d['duration'])
                result.append(d)
        return result;
        

class GetAllUDPConns(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"conv,udp\"".format(**newdict)
        return cmd
        
    def parse_command(self):
        pat = re.compile(("(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s*<->\s*"
            "(?P<dest_ip>[\d\.]+):(?P<dest_port>\d+)\s+(?P<dframes>\d+)\s+"
            "(?P<dbytes>\d+)\s+(?P<uframes>\d+)\s+(?P<ubytes>\d+)\s+"
            "(?P<tframes>\d+)\s+(?P<tbytes>\d+)\s+(?P<start>[\d\.]+)\s+(?P<duration>[\d\.]+)"))
            
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            match = pat.match(line)
            if match:
                d = match.groupdict()
                d['type'] = 'UDP'
                d['duration_f'] = float(d['duration'])
                result.append(d)
        return result;

# Input parameters: filename, src_ip, src_port, dest_ip, dest_port, outfilename
class FilterTCPConn(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -r {filename} -Y \"(ip.addr=={src_ip} && tcp.port=={src_port} " \
            "&& ip.addr=={dest_ip} && tcp.port=={dest_port})\"  -w {outfilename}").format(**newdict)
        return cmd
                
    def parse_command(self):
        return None
          
# Input parameters: filename, src_ip, src_port, dest_ip, dest_port, outfilename
class FilterUDPConn(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -r {filename} -Y \"(ip.addr=={src_ip} && udp.port=={src_port} " \
            "&& ip.addr=={dest_ip} && udp.port=={dest_port})\"  -w {outfilename}").format(**newdict)
        return cmd
                
    def parse_command(self):
        return None
        
# Input parameters: filename
class CapInfos(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['capinfos'] = self.config.get('capinfos')
        cmd = "{capinfos} {filename}".format(**newdict);
        return cmd
                
    def parse_command(self):
        result = dict()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            fields = line.split(':', 1)
            if len(fields) < 2:
                continue
            (field, value) = fields
            field = field.strip()
            value = value.strip()
            result[field] = value
            
        return result


# Input parameters: filename, duration
class FlowInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"io,stat,{duration}\"".format(**newdict)
        return cmd
                
    def parse_command(self):
    
        pat = re.compile(r'\|\s*(?P<start>[\d\.]+)\s*<>\s*(?P<end>Dur|[\d\.]+)\s*\|\s*(?P<frames>\d+)\s*\|\s*(?P<bytes>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result;
    
    
        
# Input parameters: filename
class iSCSISRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"scsi,srt,0\"".format(**newdict)
        return cmd
                
    def parse_command(self):
    
        pat = re.compile(r'(?P<proc>[\w\d\s\-()]+)\s+(?P<calls>\d+)\s+(?P<minSRT>[\d\.]+)\s+(?P<maxSRT>[\d\.]+)\s+(?P<avgSRT>[\d\.]+)')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                d['proc'] = d['proc'].strip()
                result.append(d)
        
        return result
    
# Input parameters: filename
class iSCSIReadSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"iscsi.datasegmentlength and iscsi.opcode==0x25\"," \
            "\"AVG(iscsi.datasegmentlength)iscsi.datasegmentlength and iscsi.opcode==0x25\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<frames>\d+)\s*\|\s*(?P<bytes>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]
        
# Input parameters: filename
class iSCSIWriteSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"iscsi.scsicommand.expecteddatatransferlength and scsi_sbc.opcode==0x2a\"," \
            "\"AVG(iscsi.scsicommand.expecteddatatransferlength)iscsi.scsicommand.expecteddatatransferlength and " \
            "scsi_sbc.opcode==0x2a\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<frames>\d+)\s*\|\s*(?P<bytes>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]        

# Input parameters: filename,src_ip,dest_ip
class TCPRetrans(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0,tcp.analysis.retransmission," \
            "\"tcp.analysis.retransmission and ip.src=={src_ip}\"," \
            "\"tcp.analysis.retransmission and ip.src=={dest_ip}\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<tf>\d+)\s*\|\s*(?P<tb>\d+)\s*\|\s*(?P<sf>\d+)\s*\|\s*(?P<sb>\d+)\s*\|\s*(?P<df>\d+)\s*\|\s*(?P<db>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]     
    
# Input parameters: filename
class TCPSACK(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z io,stat,0,\"tcp.option_kind==5\"".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]           
        
# Input parameters: filename,src_ip,dest_ip
class TCPZeroWin(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z \"io,stat,0,tcp.analysis.zero_window\"," \
            "\"tcp.analysis.zero_window and ip.src=={src_ip}\",\"tcp.analysis.zero_window and ip.src=={dest_ip}\"").format(**newdict);
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<tf>\d+)\s*\|\s*(?P<tb>\d+)\s*\|\s*(?P<sf>\d+)\s*\|\s*(?P<sb>\d+)\s*\|\s*(?P<df>\d+)\s*\|\s*(?P<db>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]           

        
# Input parameters: filename,src_ip,dest_ip
class TCPDelayACK(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0,\"tcp.len==0\"," \
            "\"tcp.analysis.ack_rtt >0.19 and tcp.len==0 and ip.src=={src_ip}\"," \
            "\"tcp.analysis.ack_rtt >0.19 and tcp.len==0 and ip.src=={dest_ip}\"").format(**newdict);
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<tf>\d+)\s*\|\s*(?P<tb>\d+)\s*\|\s*(?P<sf>\d+)\s*\|\s*(?P<sb>\d+)\s*\|\s*(?P<df>\d+)\s*\|\s*(?P<db>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                # convert each value of the key 
                # as integer
                d_i = {}
                for (k, v) in d.items():
                    d_i[k + "_i"] = int(v)
                d.update(d_i)   
                result.append(d)

        return result[0]           
        
# Input parameters: filename
class UDPTTLExceeded(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z io,stat,0,\"icmp.code==1\"".format(**newdict);
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|')
 
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
                
        if len(result) == 0:
            # nothing is matched, put 0 then
            result.append({
                'f' : '0',
                'b' : '0'
                })
       
        return result[0]
        
# Input parameters: filename
class SMBSRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"smb,srt\"".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat_header = re.compile(r'(?P<cat>[\w\s()]+)\s+Calls\s+Min\s+SRT\s+Max\s+SRT\s+Avg SRT')
        pat_line = re.compile(r'(?P<proc>[\w\s()]+)\s+(?P<calls>\d+)\s+(?P<minSRT>[\d\.]+)\s+(?P<maxSRT>[\d\.]+)\s+(?P<avgSRT>[\d\.]+)')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        header = None
        cur_list = list()
        
        
        for line in lines:
            header_match = pat_header.match(line)
            if header_match:
                # flush previous
                if not header == None:
                    item = dict()
                    item['cat'] = header.strip()
                    item['list']= cur_list
                    result.append(item)
                header = header_match.groupdict()['cat'].strip()
                cur_list = list()
            
            line_match = pat_line.match(line)
            if line_match:
                d = line_match.groupdict()
                d['proc'] = d['proc'].strip()
                cur_list.append(d)
                
        # flush final
        item = dict()
        item['cat'] = header
        item['list']= cur_list
        result.append(item)
        return result
        

# Input parameters: filename
class SMBReadSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"smb.file.rw.length and smb.cmd==0x2e and smb.flags.response==1\"," \
            "\"AVG(smb.file.rw.length)smb.file.rw.length and smb.cmd==0x2e and smb.flags.response==1\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]            
        
# Input parameters: filename
class SMBWriteSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"smb.file.rw.length and smb.cmd==0x2f and smb.flags.response==1\"," \
            "\"AVG(smb.file.rw.length)smb.file.rw.length and smb.cmd==0x2f and smb.flags.response==1\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]               

# Input parameters: filename
class SMB2ReadSRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"smb2.cmd==8 and smb2.time\",\"MAX(smb2.time)smb2.time and smb2.cmd==8\"," \
            "\"AVG(smb2.time)smb2.time and smb2.cmd==8\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<max>[\d\.]+)\s*\|\s*(?P<avg>[\d\.]+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]           

class SMB2WriteSRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"smb2.cmd==9 and smb2.time\",\"MAX(smb2.time)smb2.time and smb2.cmd==9\"," \
            "\"AVG(smb2.time)smb2.time and smb2.cmd==9\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<max>[\d\.]+)\s*\|\s*(?P<avg>[\d\.]+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]    
        
        
# Input parameters: filename
class SMB2ReadSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"smb2.read_length and smb2.flags.response==1\"," \
            "\"AVG(smb2.read_length)smb2.read_length and smb2.flags.response==1\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<avg>[\d\.]+)\s*\|')
        
        
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]               
        
# Input parameters: filename
class SMB2WriteSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"smb2.cmd==8 and smb2.time\",\"MAX(smb2.time)smb2.time and smb2.cmd==8\"," \
            "\"AVG(smb2.time)smb2.time and smb2.cmd==8\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<max>[\d\.]+)\s*\|\s*(?P<avg>[\d\.]+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]   
        

# Input parameters: filename
class NFSV3SRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"rpc,srt,100003,3\"".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'(?P<proc>[\w\d\s\-()]+)\s+(?P<calls>\d+)\s+(?P<minSRT>[\d\.]+)\s+(?P<maxSRT>[\d\.]+)\s+(?P<avgSRT>[\d\.]+)\s+(?P<total>[\d\.]+)')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                d['proc'] = d['proc'].strip()
                result.append(d)
        
        return result  

        
# Input parameters: filename
class NFSV3ReadSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"rpc.time and rpc.program==100003 and rpc.programversion==3 and rpc.procedure==6\"," \
            "\"SUM(nfs.count3)nfs.count3 and rpc.programversion==3 and rpc.procedure==6 and rpc.msgtyp==1\"," \
            "\"AVG(nfs.count3)nfs.count3 and rpc.programversion==3 and rpc.procedure==6 and rpc.msgtyp==1\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<s>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]           
        
# Input parameters: filename
class NFSV3WriteSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = ("{tshark} -n -q -r {filename} -z io,stat,0," \
            "\"rpc.time and rpc.program==100003 and rpc.programversion==3 and rpc.procedure==7\"," \
            "\"SUM(nfs.count3)nfs.count3 and rpc.programversion==3 and rpc.procedure==7 and rpc.msgtyp==1\"," \
            "\"AVG(nfs.count3)nfs.count3 and rpc.programversion==3 and rpc.procedure==7 and rpc.msgtyp==1\"").format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<s>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]          
       


# Input parameters: filename
class NFSV4ReadSRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"rpc,srt,100003,4,nfs.opcode==25\"".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'(?P<proc>[\w\s()]+)\s+(?P<calls>\d+)\s+(?P<minSRT>[\d\.]+)\s+(?P<maxSRT>[\d\.]+)\s+(?P<avgSRT>[\d\.]+)\s+(?P<total>[\d\.]+)')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                d['proc'] = d['proc'].strip()
                result.append(d)
        
        if len(result) == 0:
            # Nothing found, make a fake one
            result.append(
                {
                    'proc': '<UNKNOWN>',
                    'calls': '0',
                    'minSRT': '0.00',
                    'maxSRT': '0.00',
                    'avgSRT': '0.00',
                    'total': '0.00',
                }
            )
        return result[0]            

class NFSV4WriteSRTInfo(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z \"rpc,srt,100003,4,nfs.opcode==38\"".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'(?P<proc>[\w\s()]+)\s+(?P<calls>\d+)\s+(?P<minSRT>[\d\.]+)\s+(?P<maxSRT>[\d\.]+)\s+(?P<avgSRT>[\d\.]+)\s+(?P<total>[\d\.]+)')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                d['proc'] = d['proc'].strip()
                result.append(d)
        return result[0]          
        
        
# Input parameters: filename
class NFSV4ReadSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z io,stat,0,nfs.read.data_length,AVG(nfs.read.data_length)".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]   
        
# Input parameters: filename
class NFSV4WriteSize(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z io,stat,0,nfs.write.data_length,AVG(nfs.write.data_length)".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<f>\d+)\s*\|\s*(?P<b>\d+)\s*\|\s*(?P<avg>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
        return result[0]          

# Input parameters: filename
class SMBType(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z io,stat,0,smb,smb2".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<smbf>\d+)\s*\|\s*(?P<smbb>\d+)\s*\|\s*(?P<smb2f>\d+)\s*\|\s*(?P<smb2b>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)
            
        # if nothing is found, give a default
        if len(result) == 0:
                result.append({
                    'smbf' : '0',
                    'smbb' : '0',
                    'smb2f' : '0',
                    'smb2b' : '0',
                })    
                
        return result                   
     
# Input parameters: filename
class NFSType(BaseCommand):
    def compose_command(self):
        newdict = dict(self.params)
        newdict['tshark'] = self.config.get('tshark')
        cmd = "{tshark} -n -q -r {filename} -z io,stat,0,\"rpc.programversion==3\",\"rpc.programversion==4\"".format(**newdict)
        return cmd
                
    def parse_command(self):
        pat = re.compile(r'\|\s*([\d\.]+)\s*<>\s*([\d\.]+)\s*\|\s*(?P<nfsv3f>\d+)\s*\|\s*(?P<nfsv3b>\d+)\s*\|\s*(?P<nfsv4f>\d+)\s*\|\s*(?P<nfsv4b>\d+)\s*\|')
        
        result = list()
        lines = self.raw_output.split('\n')
        
        for line in lines:
            
            match = pat.match(line)
            if match:
                d = match.groupdict()
                result.append(d)

        return result   
 
if __name__ == '__main__':
    import sys
    import inspect
    # generate default values
    d = {
        'filename' : 'default.cap', 
        'src_ip' : '192.168.1', 
        'src_port' : 12345,
        'dest_ip' : '111.3.5.23',
        'dest_port' : 6000,
        'outfilename' : 'nfs.filter',
        'duration' : 19,
    }
    cur_mod = sys.modules[__name__]
    all = dir(cur_mod)
    all.sort()
    for c in all:
        aKlass = getattr(cur_mod, c)
        if inspect.isclass(aKlass) and issubclass(aKlass, BaseCommand) and (aKlass is not BaseCommand):
            dd = dict(d)
            inst = aKlass(dd)
            print "{}: {}".format(c, inst.get_command())
            print
        
    