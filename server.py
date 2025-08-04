#!/usr/bin/python3
import argparse
import errno
import os
import re
import sys
import syslog
import time
from multiprocessing import Manager, Process
from socket import AF_INET, SOCK_DGRAM, socket

import deamonize
import misc_util
from zbxsend import Metric, send_to_zabbix

__all__ = ["Server"]


def run_socket(buf_len, data, hostname, port):
    ### Setup listening thread ###
    ### This needs a signal_handler to handle signals cleanly ###
    import signal

    addr = (hostname, port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(addr)

    def signal_handler(signal, frame):
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    while True:
        buf, addr = sock.recvfrom(buf_len)
        host, _ = addr
        data.append((buf, host))


def do_send(zabbix_host, zabbix_port, metrics_list, disco_list, sleep_len):
    ### Setup Zabbix sender thread ###
    ### This needs a signal_handler to handle signals cleanly ###
    import signal

    def signal_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    while True:
        d_sub = []
        while len(disco_list) > 0:
            disco_item = disco_list.pop()
            d_sub.extend(disco_item)
        if len(d_sub) > 0:
            send_to_zabbix(d_sub, zabbix_host, zabbix_port, 15, False)
            # Send Autodiscovery 'metrics' to zabbix before data to allow for item creation
        pending = len(metrics_list)
        metrics = []
        if pending > 0:
            for x in range(pending):
                metrics.extend(metrics_list.pop())
            send_to_zabbix(metrics, zabbix_host, zabbix_port, 15, False)
            # Send regular metrics to zabbix
        time.sleep(int(sleep_len / 1000))


def syslog_print(message):
    syslog.syslog(message)


def stdout_print(message):
    print(message)


class Server(object):

    def __init__(
        self,
        pct_threshold=90,
        debug=False,
        zabbix_host="localhost",
        zabbix_port=10051,
        flush_interval=10000,
        override_host=None,
    ):
        self.buf = 10240
        self.flush_interval = flush_interval
        self.pct_threshold = pct_threshold
        self.zabbix_host = zabbix_host
        self.zabbix_port = zabbix_port
        self.debug = debug
        self.log = stdout_print
        self.manager = Manager()
        self.override_host = override_host

        self.counters = []
        self.timers = []
        self.gauges = []
        self.scoutFS = {}
        self.flusher = 0
        self.domain_pool = {}
        self.vol_res = {}
        self.domain_only = {}
        self.vol_only = {}
        self.scsi_drive = {}

        self.buffer = self.manager.list()
        self.metrics = self.manager.list()
        self.metrics_disco = self.manager.list()

    def process(self, data, rhost):
        print("---------------------")
        print(len(self.counters))
        print(len(self.timers))
        print(len(self.gauges))
        print(len(self.scoutFS))
        print(self.flusher)
        print(len(self.domain_pool))
        print(len(self.vol_res))
        print(len(self.domain_only))
        print(len(self.vol_only))
        print(len(self.scsi_drive))
        print(len(self.buffer))
        print(len(self.metrics))
        print(len(self.metrics_disco))
        print("---------------------")
        print("")
        datas = data.decode("utf-8")
        for line in datas.split("\n"):
            try:
                if line.count(":") == 3:
                    # Broken implementations add host infront of the key.
                    host, key, val = line.split(":")
                else:
                    # Working ones don't. Some embed data in the key.
                    # scoutam.sched.jobs,hostname=scheduler,queue=reserving,type=archive:0|g
                    longkey, val = line.split(":")
                    host = ""
                    if "," in longkey:
                        segments = longkey.split(",")
                        mkey = segments.pop(0)
                        tkey = mkey + "["
                        tmp_dict = {}
                        for seg in segments:
                            if "=" in seg:
                                key, kval = seg.split("=")
                                tmp_dict[key] = kval
                            else:
                                tkey = tkey + seg + ","
                        if len(tmp_dict) > 0:
                            if "hostname" in tmp_dict:
                                if not self.override_host == None:
                                    host = self.override_host
                                else:
                                    host = tmp_dict["hostname"]
                                del tmp_dict["hostname"]
                            if host == "":
                                # Paranoia. It looks like every message has a hostname= tag, but better safe then segfault.
                                if not self.override_host == None:
                                    host = self.override_host
                                else:
                                    host = rhost
                            if "scoutam.fs" in mkey:
                                # Zabbix Autodiscovery for fsid's but we'll build the metric via the common case.
                                if "fsid" in tmp_dict:
                                    if self.debug:
                                        self.log(tmp_dict["fsid"])
                                    fsid = tmp_dict["fsid"]
                                    if not host in self.scoutFS:
                                        self.scoutFS[host] = []
                                    if not fsid in self.scoutFS[host]:
                                        self.scoutFS[host].append(fsid)
                                    if self.debug:
                                        self.log(self.scoutFS)
                            if "scoutam.catalog" in mkey:
                                # Zabbix Autodiscovery for domain/pool combinations. We'll have to build this one explicitly
                                if "domain" in tmp_dict and "pool" in tmp_dict:
                                    dom = tmp_dict["domain"]
                                    pool = tmp_dict["pool"]
                                    tkey = tkey + dom + "," + pool + ","
                                    if not host in self.domain_pool:
                                        self.domain_pool[host] = []
                                    if (dom, pool) not in self.domain_pool[host]:
                                        self.domain_pool[host].append((dom, pool))
                                    if self.debug:
                                        self.log(tkey)
                                if "status" in tmp_dict:
                                    # Seems StatsD doesn't care about ordering. Zabbix does. So lets ensure it's consistent
                                    stat = tmp_dict["status"]
                                    tkey = tkey + stat + ","
                            elif "scoutam.exec" in mkey:
                                # Zabbix Autodiscovery for the exec tree of values. Explict build required
                                if "domain" in tmp_dict and "type" in tmp_dict:
                                    # Type, domain
                                    tdata = tmp_dict["type"]
                                    dom = tmp_dict["domain"]
                                    tkey = tkey + tdata + "," + dom + ","
                                    if not host in self.domain_only:
                                        self.domain_only[host] = []
                                    if dom not in self.domain_only[host]:
                                        self.domain_only[host].append(dom)
                                elif "volume" in mkey and "resource" in mkey:
                                    # Type,volume,resource
                                    vol = tmp_dict["volume"]
                                    res = tmp_dict["resource"]
                                    tdata = tmp_dict["type"]
                                    tkey = tkey + tdata + "," + vol + "," + res + ","
                                    if not host in self.vol_res:
                                        self.vol_res[host] = []
                                    if (vol, res) not in self.vol_res[host]:
                                        self.vol_res[host].append((vol, res))
                                else:
                                    # Type, Volume
                                    tdata = tmp_dict["type"]
                                    vol = tmp_dict["volume"]
                                    tkey = tkey + tdata + "," + vol + ","
                                    if not host in self.vol_only:
                                        self.vol_only[host] = []
                                    if vol not in self.vol_only[host]:
                                        self.vol_only[host].append(vol)
                            elif "scoutam.scsi" in mkey:
                                # Zabbix Autodiscovery for the tape drive metrics
                                drive = tmp_dict["drive"]
                                command = tmp_dict["command"]
                                tkey = tkey + drive + "," + command + ","
                                if not host in self.scsi_drive:
                                    self.scsi_drive[host] = []
                                if not (drive, command) in self.scsi_drive[host]:
                                    self.scsi_drive[host].append((drive, command))
                            else:
                                # Common case for building the metric
                                for dkey in tmp_dict:
                                    tkey = tkey + tmp_dict[dkey] + ","

                        # Clean up of trailing stuff
                        if tkey[-1] == ",":
                            key = tkey[:-1] + "]"
                        elif tkey[-1] == "[":
                            key = tkey[:-1]
                        else:
                            key = tkey

                    else:
                        key = longkey
                        host = rhost

            except ValueError:
                self.log("Got invalid data packet. Skipping")
                if self.debug:
                    self.log("DEBUG:Data packet dump: %r" % datas)
                return

            if self.debug:
                self.log((host, key))

            sample_rate = 1
            fields = val.split("|")

            if fields[1] == "ms":
                # Timestamps are unix time or count in ms.
                self.timers.append((host, key, int(fields[0] or 0), int(time.time())))
            elif fields[-1] == "g":
                # Raw guage values
                self.gauges.append((host, key, int(fields[0]), int(time.time())))
            else:
                # Counters can contain weird rate modifiers
                if len(fields) == 3:
                    sample_rate = float(
                        re.match(
                            "^@([\\d\\.]+)", fields[2]
                        ).groups()[  # pyright: ignore
                            0
                        ]
                    )
                self.counters.append(
                    (
                        host,
                        key,
                        int(fields[0] or 1) * (1 / sample_rate),
                        int(time.time()),
                    )
                )

    def flush(self):
        stats = 0

        metrics = []
        if len(self.domain_pool) > 0:
            for h in self.domain_pool:
                if len(self.domain_pool[h]) > 0:
                    v = "[\n"
                    first = True
                    for d, p in self.domain_pool[h]:
                        if not first:
                            v = v + "\t,\n"
                        first = False
                        v = v + "\t{\n"
                        v = v + '\t\t"{#DOMAIN}":"' + d + '",\n'
                        v = v + '\t\t"{#POOL}":"' + p + '"\n'
                        v = v + "\t}\n"

                    v = v + "]\n"
                    stats += 1
                    if self.debug:
                        self.log(v)
                    self.metrics_disco.append(
                        [Metric(h, "scoutam.catalog.discovery", v, int(time.time()))]
                    )

        if len(self.vol_res) > 0:
            for h in self.vol_res:
                if len(self.vol_res[h]) > 0:
                    v = "[\n"
                    first = True
                    for d, p in self.vol_res[h]:
                        if not first:
                            v = v + "\t,\n"
                        first = False
                        v = v + "\t{\n"
                        v = v + '\t\t"{#VOLUME}":"' + d + '",\n'
                        v = v + '\t\t"{#RESOURCE}":"' + p + '"\n'
                        v = v + "\t}\n"

                    v = v + "]\n"
                    stats += 1
                    if self.debug:
                        self.log(v)
                    self.metrics_disco.append(
                        [Metric(h, "scoutam.exec.vol_res_disc", v, int(time.time()))]
                    )

        if len(self.scsi_drive) > 0:
            for h in self.scsi_drive:
                if len(self.scsi_drive[h]) > 0:
                    v = "[\n"
                    first = True
                    for d, p in self.scsi_drive[h]:
                        if not first:
                            v = v + "\t,\n"
                        first = False
                        v = v + "\t{\n"
                        v = v + '\t\t"{#DRIVE}":"' + d + '",\n'
                        v = v + '\t\t"{#COMMAND}":"' + p + '"\n'
                        v = v + "\t}\n"

                    v = v + "]\n"
                    stats += 1
                    if self.debug:
                        self.log(v)
                    self.metrics_disco.append(
                        [Metric(h, "scoutam.scsi.discovery", v, int(time.time()))]
                    )

        if len(self.domain_only) > 0:
            for h in self.domain_only:
                if len(self.domain_only[h]) > 0:
                    v = "[\n"
                    first = True
                    for fs in self.domain_only[h]:
                        if not first:
                            v = v + "\t,\n"
                        first = False
                        v = v + "\t{\n"
                        v = v + '\t\t"{#DOMAIN}":"' + fs + '"\n'
                        v = v + "\t}\n"

                    v = v + "]\n"

                    stats += 1
                    if self.debug:
                        self.log(v)
                    self.metrics_disco.append(
                        [Metric(h, "scoutam.exec.dom_only_disc", v, int(time.time()))]
                    )

        if len(self.vol_only) > 0:
            for h in self.vol_only:
                if len(self.vol_only[h]) > 0:
                    v = "[\n"
                    first = True
                    for fs in self.vol_only[h]:
                        if not first:
                            v = v + "\t,\n"
                        first = False
                        v = v + "\t{\n"
                        v = v + '\t\t"{#VOL}":"' + fs + '"\n'
                        v = v + "\t}\n"

                    v = v + "]\n"

                    stats += 1
                    if self.debug:
                        self.log(v)
                    self.metrics_disco.append(
                        [Metric(h, "scoutam.exec.vol_only_disc", v, int(time.time()))]
                    )

        if len(self.scoutFS) > 0:
            for h in self.scoutFS:
                if len(self.scoutFS[h]) > 0:
                    v = "[\n"
                    first = True
                    for fs in self.scoutFS[h]:
                        if not first:
                            v = v + "\t,\n"
                        first = False
                        v = v + "\t{\n"
                        v = v + '\t\t"{#FSID}":"' + fs + '"\n'
                        v = v + "\t}\n"

                    v = v + "]\n"

                    stats += 1
                    if self.debug:
                        self.log(v)
                    self.metrics_disco.append(
                        [Metric(h, "scoutam.fs_discovery", v, int(time.time()))]
                    )

        for h, k, v, ts in self.counters:

            metrics.append(Metric(h, k, str(v), ts))

            stats += 1
        self.counters[:] = []

        for h, k, v, ts in self.gauges:

            metrics.append(Metric(h, k, str(v), ts))

            stats += 1
        self.gauges[:] = []

        for h, k, v, ts in self.timers:
            if len(v) > 0:
                v.sort()
                count = len(v)
                min = v[0]
                max = v[-1]

                mean = min
                max_threshold = max
                median = min

                if count > 1:
                    thresh_index = int(round(count * float(self.pct_threshold) / 100))
                    max_threshold = v[thresh_index - 1]
                    total = sum(v[:thresh_index])
                    mean = total / thresh_index

                    if count % 2 == 0:
                        median = (v[count / 2] + v[count / 2 - 1]) / 2.0
                    else:
                        median = v[count / 2]

                host, key = k.split(":", 1)
                metrics.extend(
                    [
                        Metric(host, key + "[mean]", mean, ts),
                        Metric(host, key + "[upper]", max, ts),
                        Metric(host, key + "[lower]", min, ts),
                        Metric(host, key + "[count]", count, ts),
                        Metric(
                            host,
                            key + "[upper_%s]" % self.pct_threshold,
                            max_threshold,
                            ts,
                        ),
                        Metric(host, key + "[median]", median, ts),
                    ]
                )

                stats += 1
        self.gauges[:] = []

        if len(metrics) > 0:
            self.metrics.append(metrics)

        if self.debug:
            self.log(metrics)

    def serve(
        self,
        hostname="",
        port=8126,
        zabbix_host="localhost",
        zabbix_port=2003,
        log=stdout_print,
    ):
        # assert type(port) is types.IntType, "port is not an integer: %s" % (port)
        # run_socket() self.buffer
        # run_socket(self.buf,data,hostname,port)
        self.listen_p = Process(
            target=run_socket, args=(self.buf, self.buffer, hostname, port)
        )
        self.listen_p.start()
        self.zabbix_host = zabbix_host
        self.zabbix_port = zabbix_port
        self.log = log
        self.send_p = Process(
            target=do_send,
            args=(
                self.zabbix_host,
                self.zabbix_port,
                self.metrics,
                self.metrics_disco,
                self.flush_interval,
            ),
        )
        self.send_p.start()

        import signal

        def signal_handler(signal, frame):
            self.stop()

        signal.signal(signal.SIGINT, signal_handler)

        # self._set_timer()
        while True:
            if len(self.buffer) > 0:
                data, host = self.buffer.pop()
                self.process(data, host)
                self.flush()
            time.sleep(0.1)

    def stop(self):
        self.listen_p.join(1)
        self.send_p.join(1)
        # self._sock.close()
        sys.exit(0)


def main_loop(config, log):
    if "override_host" in config["main"]:
        server = Server(
            pct_threshold=int(config["main"]["stats_pct_threshold"]),
            debug=config["main"]["debug"],
            flush_interval=int(config["main"]["flush_interval"]),
            override_host=config["main"]["override_host"],
        )
    else:
        server = Server(
            pct_threshold=int(config["main"]["stats_pct_threshold"]),
            debug=config["main"]["debug"],
            flush_interval=int(config["main"]["flush_interval"]),
        )

    server.serve(
        "",
        int(config["main"]["port"]),
        config["zabbix"]["server"],
        int(config["zabbix"]["port"]),
        log,
    )


def main():
    opt = setup_base_args()
    arg = opt.parse_args()
    arg_dict = vars(arg)
    config = []

    # Load config and abort if not found
    if os.path.exists(arg_dict["config"]):
        config = misc_util.load_multi_mod_config(arg_dict["config"])
    else:
        print("No config file found")
        quit()
    if len(arg_dict["action"]) > 0:
        if arg_dict["action"][0] == "start":

            # Are we systemd or should we call syslog ourselves
            if config["main"]["systemd"]:  # pyright: ignore
                log = stdout_print
                log("SystemD mode startup")
                pid = os.getpid()
                fpid = open(config["main"]["pidfile"], "wb")  # pyright: ignore
                fpid.write(str(pid).encode("utf-8"))
                fpid.close()
                main_loop(config, log)
            else:
                log = syslog_print
                log("Syslog mod startup")
                deamonize.daemonize_agent(
                    stdout_log="/dev/null",
                    stderr_log="/dev/null",
                    pidfile=config["main"]["pidfile"],  # pyright: ignore
                )
                main_loop(config, log)
        elif arg_dict["action"][0] == "status":
            if not os.path.exists(config["main"]["pidfile"]):  # pyright: ignore
                print("Not running")
                quit()
            else:
                pidfile = open(config["main"]["pidfile"], "r")  # pyright: ignore
                pid = pidfile.read()
                found = False
                if int(pid) > 0:
                    try:
                        os.kill(int(pid), 0)
                    except OSError as err:
                        if err.errno == errno.EPERM:
                            found = True
                    else:
                        found = True
                if found:
                    print("Running with pid " + pid.strip())
                    quit()
                else:
                    print("Pid file exists but not running")
                    print("Cleaning Pid file")
                    os.remove(config["main"]["pidfile"])  # pyright: ignore
                    quit()
        elif arg_dict["action"][0] == "stop":
            if not os.path.exists(config["main"]["pidfile"]):  # pyright: ignore
                print("Not running")
                quit()
            else:
                pidfile = open(config["main"]["pidfile"], "r")  # pyright: ignore
                pid = int(pidfile.read().strip())
                try:
                    while 1:
                        import signal

                        os.kill(pid, signal.SIGTERM)
                        time.sleep(0.1)
                except OSError as err:
                    errtext = str(err)
                    if errtext.find("No such process") > 0:
                        if os.path.exists(config["main"]["pidfile"]):  # pyright: ignore
                            os.remove(config["main"]["pidfile"])  # pyright: ignore
                    else:
                        print(errtext)
                        quit()


def setup_base_args():
    opt = argparse.ArgumentParser(description="Xenon ScoutAM StatsD Zabbix adapter")
    opt.add_argument(
        "--config",
        action="store",
        default="/etc/xssza.conf",
        dest="config",
        help="Config file location",
    )
    opt.add_argument(
        "action",
        type=str,
        nargs="+",
        help="Specify action start,stop and status are valid",
    )

    return opt


if __name__ == "__main__":
    main()
