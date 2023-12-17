__all__ = ['GlobalConfig']

default_config = {
    'port' : 8080,
    #'port' : 9000,
    'host' : '0.0.0.0',
    
    # Dev home
    #'save_dir' : "E:\\Work\\SaveTemp\\",
    #'tshark' : "\"C:\\Program Files\\Wireshark\\tshark.exe\"",
    #'capinfos' : "\"C:\\Program Files\\Wireshark\\capinfos.exe\"",
    
    # Dev Demo
    'save_dir' : "C:\\Work\\STARTII\\save\\", # must end with back slash
    'tshark' : "\"C:\\Program Files\\Wireshark\\tshark.exe\"",
    'capinfos' : "\"C:\\Program Files\\Wireshark\\capinfos.exe\"",
    
    # 500 GB
    'max_space_in_mb' : 50 * 1024,
    # 2 days
    'max_keep_time_in_minute': 1 * 60 * 24,
    # check interval
    # 5 min
    'check_internal_in_second' : 5 * 60,
    
}


class GlobalConfig:
    def __init__(self):
        self.items = dict(default_config)
        
    def get(self, name):
        return self.items[name]
    
    
    
        
