#! /usr/bin/python
import fileinput
import os
import time


def sizeof_fmt(num, suffix='B', base = 1024.0):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < base:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= base
    return "%.1f%s%s" % (num, 'Yi', suffix)

def load_config(conf_path):
    tmp_config = {}
    print('Load begin')
    if os.path.exists(conf_path):
        print('Config exists loading')
        for line in fileinput.input(conf_path):
            conf_prop = line[0:line.find(':')]
            print(conf_prop)
            tmp_str = line[line.find(':')+1:].strip()
            if tmp_str.upper().strip() == "TRUE":
                tmp_config[conf_prop] = True
            elif tmp_str.upper().strip() == "FALSE":
                tmp_config[conf_prop] = False
            else:
                tmp_config[conf_prop] = tmp_str
        return tmp_config
    else:
        return None

def load_multi_mod_config(conf_path):
    tmp_config = {}
    tmp_mod_name = ''
    found = False
    print('Config load begin')
    if os.path.exists(conf_path):
        print('Config exists loading config')
        for line in fileinput.input(conf_path):
            #print(line)
            if line[0] == '[' and line.strip()[-1] == ']':
                tmp_mod_name = line[1:len(line.strip())-1]
                tmp_config[tmp_mod_name] = {}
                found = True
                #print(tmp_mod_name)
            elif (found and len(tmp_mod_name) > 0):
                conf_prop = line[0:line.find(':')]
                #print(conf_prop)
                tmp_str = line[line.find(':')+1:].strip()
                if tmp_str.upper().strip() == "TRUE":
                    tmp_config[tmp_mod_name][conf_prop] = True
                elif tmp_str.upper().strip() == "FALSE":
                    tmp_config[tmp_mod_name][conf_prop] = False
                elif tmp_str.find(',') > 0:
                    tmp_list = tmp_str.split(',')
                    tmp_list = map(str.strip, tmp_list)
                    tmp_config[tmp_mod_name][conf_prop] = tmp_list
                else:
                    tmp_config[tmp_mod_name][conf_prop] = tmp_str
            else:
                print("Something happened during loading")
                print(found)
                print(len(tmp_mod_name))
        print("Config load complete")
        return tmp_config
    else:
        print("Config invalid aborting")
        return None



def load_zabbix_config():
    port = 10051
    conf_file = '/etc/zabbix/zabbix_agentd.conf'
    if os.path.exists(conf_file):
        find = 'ServerActive='
        for line in fileinput.FileInput(conf_file):
            pos_find = line.find(find)
            if pos_find > -1 :
                pos_hash = line.find("#")
                if (pos_hash == -1) or (pos_hash > pos_find):
                    server_details = line[line.find('=')+1:].strip()
                    if pos_hash > -1:
                        server_details = server_details[:server_details.find('#')].strip()
                    pos_port= server_details.find(':')
                    if pos_port > -1:
                        port = int(server_details[pos_port+1:])
                        server = server_details[:pos_port]
                    else:
                        server = server_details
                    return (server,port)
    return (None,None)

def hour_aligned_delay(delay):
    now = time.time()
    time_tup = time.localtime()
    target_time = list(time_tup)
    target_time[4] = 0
    target_time[5] = 0
    time_tup = time.struct_time(tuple(target_time))
    time_diff = now - time.mktime(time_tup)
    time_mod = time_diff % delay
    time.sleep(delay - time_mod)
