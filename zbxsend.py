import logging
import socket
import struct
import sys
import time

try:
    import json
except:
    import simplejson as json


class Metric(object):
    def __init__(self, host, key, value, clock=None):
        self.host = host
        self.key = key
        self.value = value
        self.clock = clock

    def __repr__(self):
        if self.clock is None:
            return "Metric(%r, %r, %r)" % (self.host, self.key, self.value)
        return "Metric(%r, %r, %r, %r)" % (self.host, self.key, self.value, self.clock)


def send_to_zabbix(
    metrics, zabbix_host="127.0.0.1", zabbix_port=10051, timeout=15, debug=True
):
    """Send set of metrics to Zabbix server."""

    if debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    logger = logging.getLogger("zbxsender")
    # handler = logging.StreamHandler(sys.stdout)
    # handler.setLevel(logging.DEBUG)
    # formatter = logging.Formatter(
    #    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    # )
    # handler.setFormatter(formatter)
    # logger.addHandler(handler)

    j = json.dumps
    # Zabbix has very fragile JSON parser, and we cannot use json to dump whole packet
    metrics_data = []
    for m in metrics:
        clock = m.clock or time.time()
        metrics_data.append(
            (
                "\t\t{\n"
                '\t\t\t"host":%s,\n'
                '\t\t\t"key":%s,\n'
                '\t\t\t"value":%s,\n'
                '\t\t\t"clock":%s}'
            )
            % (j(m.host), j(m.key), j(m.value), int(clock))
        )
    json_data = ("{\n" '\t"request":"sender data",\n' '\t"data":[\n%s]\n' "}") % (
        ",\n".join(metrics_data)
    )

    data_len = struct.pack("<Q", len(json_data))
    packet = bytearray(b"ZBXD\1")
    packet.extend(data_len)
    packet.extend(json_data.encode("utf-8"))
    try:
        zabbix = socket.socket()
        zabbix.connect((zabbix_host, int(zabbix_port)))
        zabbix.settimeout(timeout)
        # send metrics to zabbix
        zabbix.sendall(packet)
        # get response header from zabbix
        resp_hdr = _recv_all(zabbix, 13)
        if not resp_hdr.startswith(b"ZBXD\1") or len(resp_hdr) != 13:
            logger.error("Wrong zabbix response")
            return False
        resp_body_len = struct.unpack("<Q", resp_hdr[5:])[0]
        # get response body from zabbix
        resp_body = zabbix.recv(resp_body_len)
        resp = json.loads(resp_body)
        logger.debug("Got response from Zabbix: %s" % resp)
        logger.info(resp.get("info"))
        if resp.get("response") != "success":
            logger.error("Got error from Zabbix: %s", resp)
            return False
        return True
    except socket.timeout as e:
        logger.error("zabbix timeout: " + str(e))
        return False
    except Exception as e:
        logger.exception("Error while sending data to Zabbix: " + str(e))
        return False
    finally:
        zabbix.close()


def _recv_all(sock, count):
    buf = bytearray(b"")
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            return buf
        buf.extend(chunk)
    return buf


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    send_to_zabbix([Metric("localhost", "bucks_earned", 99999)], "localhost", 10051)
