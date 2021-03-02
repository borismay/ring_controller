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


PING_PACKETS = 1
PING_TIMEOUT_SEC = 3
PING_PACKET_SIZE_BYTES = 1
DELAY_BETWEEN_PING_TEST_SEC = 5
N_CONSECUTIVE_PINGS_LOST = 4
EXIT_ON_FAULT = True
UNITS_FILENAME = r'ring_controller_ips.csv'



class UnitPing:
    def __init__(self, ip, ping_packets=PING_PACKETS, ping_timeout_sec=PING_TIMEOUT_SEC, ping_packet_size_bytes=PING_PACKET_SIZE_BYTES):
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


def find_first_unconnected_ip(unconnected_ips, all_ips_ordered):
    for ip in all_ips_ordered:
        if ip in unconnected_ips:
            return ip


def find_last_connected_ip(unconnected_ip, all_ips_ordered):
    last_connected_index = all_ips_ordered.index(unconnected_ip) - 1
    return all_ips_ordered[last_connected_index]


def activate_rpl(unit):
    rpl_ip = unit['IP'].values[0]
    print(f'Activating RPL of {rpl_ip}')
    return


def disconnect_last_connected_unit(unit):
    # check the connection type of the last connected unit
    connection_to_the_next_unit = unit['ConnectionToNextRadio'].values[0]
    last_connected_ip = unit['IP'].values[0]

    if connection_to_the_next_unit == 'rf':
        print(f'Connection to the next unit is RF. Need to turn on ALIGNMENT of {last_connected_ip}')
    else:
        print(
            f'Connection to the next unit is Ethernet. Need to turn down {connection_to_the_next_unit} of {last_connected_ip}')
    return


if __name__ == "__main__":
    units_in_ring = pd.read_csv(UNITS_FILENAME)

    ips_to_ping = units_in_ring[units_in_ring['Type'] == 'BH']['IP'].tolist()
    cw_ips = units_in_ring[(units_in_ring['Type'] == 'BH') & (units_in_ring['Direction'] == 'CW')]['IP'].tolist()
    acw_ips = units_in_ring[(units_in_ring['Type'] == 'BH') & (units_in_ring['Direction'] == 'ACW')]['IP'].tolist()

    while True:
        print('Pinging units...')
        results = ping_all_units(ips_to_ping)
        all_alive = sum([is_alive for ip, is_alive in results]) == len(ips_to_ping)

        if all_alive:
            print('All units alive.')
            print(f'Sleeping for {DELAY_BETWEEN_PING_TEST_SEC} seconds.')
            time.sleep(DELAY_BETWEEN_PING_TEST_SEC)
            continue

        else:
            print('At least one unit is disconnected!')
            # at least one IP is not connected
            # wait until there are N_CONSECUTIVE_PINGS_LOST
            for i in range(N_CONSECUTIVE_PINGS_LOST):
                print(f'Checking ping {i + 1}')
                results = ping_all_units(ips_to_ping)
                all_alive = sum([is_alive for ip, is_alive in results]) == len(ips_to_ping)
                if all_alive:
                    break

            if all_alive:
                print('All units reconnected. Back to normal.')
                continue

            print(f'{N_CONSECUTIVE_PINGS_LOST} pings lost. Need to activate RPL.')
            not_connected_ips = [ip for ip, is_alive in results if not is_alive]
            print('Not connected IPs:')
            print(not_connected_ips)

            # check the unconnected side
            if (units_in_ring[units_in_ring["IP"].isin(not_connected_ips)]["Direction"] == 'CW').all():
                unconnected_direction = 'CW'
                # if the disconnect is on the CW side, the RPL should be activated on the ACW side
                rpl_side = 'ACW'
                first_unconnected_ip = find_first_unconnected_ip(not_connected_ips, cw_ips)
                last_connected_ip = find_last_connected_ip(first_unconnected_ip, cw_ips)
            elif (units_in_ring[units_in_ring["IP"].isin(not_connected_ips)]["Direction"] == 'ACW').all():
                unconnected_direction = 'ACW'
                # if the disconnect is on the ACW side, the RPL should be activated on the CW side
                rpl_side = 'CW'
                first_unconnected_ip = find_first_unconnected_ip(not_connected_ips, acw_ips)
                last_connected_ip = find_last_connected_ip(first_unconnected_ip, acw_ips)
            else:
                print(f'Units disconnected on both directions. Exiting...')
                break

            print(f'Unconnected direction: {unconnected_direction}')
            print(f'First unconnected IP: {first_unconnected_ip}')

            # disconnect the last connected unit
            disconnect_last_connected_unit(units_in_ring[units_in_ring["IP"] == last_connected_ip])

            # activate RPL
            rpl_activation_unit = units_in_ring[
                (units_in_ring["ConnectionToNextRadio"] == 'rpl') &
                (units_in_ring["Direction"] == rpl_side)
            ]
            activate_rpl(rpl_activation_unit)

            # exit if a fault was detected
            if EXIT_ON_FAULT:
                print('Exiting...')
                break
