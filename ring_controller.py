# from siklu_api import *
from pythonping import ping

from multiprocessing import Pool
from subprocess import call

import pandas as pd
import time

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0


class UnitPing:
    def __init__(self, ip, ping_packets=1, ping_timeout_sec=3, ping_packet_size_bytes=1):
        self.ip = ip
        self.ping_packets = ping_packets
        self.ping_timeout_sec = ping_timeout_sec
        self.ping_packet_size_bytes = ping_packet_size_bytes
        self.packet_loss = 0
        self.rtt_avg_ms = 0

    def is_reachable(self):
        reply = ping(self.ip, count=self.ping_packets, timeout=self.ping_timeout_sec, size=self.ping_packet_size_bytes)
        self.packet_loss = reply.packet_loss
        self.rtt_avg_ms = reply.rtt_avg_ms
        return self.packet_loss == 0


def ping_unit(unit):
    return [unit.ip, unit.is_reachable()]


def ping_all_units(ips):
    pool = Pool(processes=len(ips))
    units = [UnitPing(ip) for ip in ips]
    replies = pool.map(ping_unit, units)
    pool.close()
    pool.join()
    return replies


def tests():
    # ips = ['192.168.1.33', '142.250.72.206']
    # reply = ping(TEST_IP, count=PING_PACKETS, timeout=PING_TIMEOUT_SEC, size=PING_PACKET_SIZE_BYTES)
    # print(f'RTT ms: {reply.rtt_avg_ms}')
    # print(f'Packet loss: {reply.packet_loss}')
    #
    # u0 = UnitPing(ips[0])
    # u0.is_reachable()
    # u1 = UnitPing(ips[1])
    # u1.is_reachable()
    return


if __name__ == "__main__":
    PING_PACKETS = 1
    PING_TIMEOUT_SEC = 3
    PING_PACKET_SIZE_BYTES = 1
    DELAY_BETWEEN_PING_TEST_SEC = 5

    UNITS_FILENAME = r'ring_controller_ips.csv'
    units_in_ring = pd.read_csv(UNITS_FILENAME)

    ips_to_ping = units_in_ring[units_in_ring['Type'] == 'BH']['IP'].tolist()

    while True:
        print('Pinging units...')
        results = ping_all_units(ips_to_ping)
        all_alive = sum([is_alive for ip, is_alive in results]) == len(ips_to_ping)

        if all_alive:
            print('All units alive.')
        else:
            not_connected_ips = [ip for ip, is_alive in results if not is_alive]
            print('Not connected IPs:')
            print(not_connected_ips)

        print(f'Sleeping for {DELAY_BETWEEN_PING_TEST_SEC} seconds.')
        time.sleep(DELAY_BETWEEN_PING_TEST_SEC)
