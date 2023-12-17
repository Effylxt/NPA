#!/usr/bin/env python
# -*- coding: utf-8 -*-


import sys
from config import GlobalConfig
from webapp import app
from task import *
from freespace import *

conf = GlobalConfig()

if __name__ == '__main__':
    flask_options = dict(
        host=conf.get('host'),
        debug=True,
        port=conf.get('port'),
        threaded=True,
        )

    get_task_manager().start()
    startSpaceMonitor()
    
    app.run(**flask_options)

