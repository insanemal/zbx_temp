#!/usr/bin/python

import os
import sys


def daemonize_agent(stdout_log='/var/log/default.log', stderr_log='/var/log/default.err', pidfile='/var/run/default.pid', home_dir='.'):
    """ Make the agent a daemon.  """
    try:
        # Inital fork
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write('Failed first fork. Terminating" (%d) %s\n' % (e.errno, e.strerror))
            os._exit(1)
        os.setsid()
        os.chdir(home_dir)
        os.umask(0)
        # Should be in new session. Final fork to to drop TTY and everything else.
        try:
            pid = os.fork()
            if pid > 0:
                fpid = open(pidfile, 'wb')
                fpid.write(str(pid).encode('utf-8'))
                fpid.close()
                os._exit(0)
        except OSError as e:
            sys.stderr.write('Failed second fork. Terminating" (%d) %s\n' % (e.errno, e.strerror))
            sys.exit(1)
        #Should be in target fork by now.....
        si = open('/dev/null', 'r')
        so = open(stdout_log, 'a+')
        se = open(stderr_log, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    except Exception as e:
        sys.stderr.write(str(e))

if __name__ == '__main__':
    print("This is supposed to be imported.")

