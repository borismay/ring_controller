################################
# TODO:
# 1. RPL commands reception acknowledge
# 2. clear FDB upon connection
# 3. second timeout for connectivity after RPL event
# 4. concurrent execution of save_running_config()

from siklu_api import *
from pythonping import ping

from multiprocessing import Pool
from subprocess import call

import pandas as pd
import time

import os
import sys

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0


PING_PACKETS = 1
PING_TIMEOUT_SEC = 1
PING_PACKET_SIZE_BYTES = 1
DELAY_BETWEEN_PING_TEST_SEC = 5
KEEP_ALIVE_SEC = 3600
N_CONSECUTIVE_PINGS_LOST = 15
WAIT_FOR_RF_SEC = 60
WAIT_FOR_AGING_SEC = 5*60
EXIT_ON_FAULT = True
UNITS_FILENAME = r'ring_controller_ips.csv'
SLACK_CHANNEL_NAME = '#welink_ring_controller'

# create an environment variable 'SLACK_BOT_TOKEN'
client = WebClient(token=os.environ['SLACK_BOT_TOKEN'])


def send_slack_message(msg):
    try:
        print(msg)
        response = client.chat_postMessage(channel=SLACK_CHANNEL_NAME, text=msg)
        assert response["message"]["text"] == msg
    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        assert e.response["ok"] is False
        assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
        print(f"Got an error: {e.response['error']}")
    except AttributeError as e:
        print(f"Got an AttributeError error")
    except:
        print("Unexpected error:", sys.exc_info()[0])


class UnitPing:
    def __init__(self, ip, ping_packets=PING_PACKETS, ping_timeout_sec=PING_TIMEOUT_SEC, ping_packet_size_bytes=PING_PACKET_SIZE_BYTES):
        self.ip = ip
        self.ping_packets = ping_packets
        self.ping_timeout_sec = ping_timeout_sec
        self.ping_packet_size_bytes = ping_packet_size_bytes
        self.packet_loss = 0
        self.rtt_avg_ms = 0

    def is_reachable(self, allow_errors=False):
        reply = ping(self.ip, count=self.ping_packets, timeout=self.ping_timeout_sec, size=self.ping_packet_size_bytes)
        self.packet_loss = reply.packet_loss
        self.rtt_avg_ms = reply.rtt_avg_ms
        if not allow_errors:
            return self.packet_loss == 0
        else:
            return self.packet_loss < 1.0


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


def save_running_config(unit):
    odu = SikluUnit(unit['IP'], unit['Username'], unit['Password'], debug=False)
    odu.connect()
    if odu.connected:
        odu.send_command('copy running-configuration startup-configuration')
        send_slack_message(f"{unit['IP']} running-configuration saved")
    else:
        send_slack_message(f"{unit['IP']} failed to save running-configuration")


def activate_rpl(unit):
    rpl_ip = unit['IP']
    command = unit['ProtectionCommand']
    send_slack_message(f'Activating RPL on {rpl_ip}')
    send_slack_message(f'Executing: {command} on {rpl_ip}')
    odu = SikluUnit(unit['IP'], unit['Username'], unit['Password'], debug=False)
    odu.connect()
    if odu.connected:
        status = odu.send_command(unit['ProtectionCommand'])
        odu.send_command('copy running-configuration startup-configuration')
    else:
        send_slack_message(f"Failed to connect to {unit['IP']}")
        return False

    return status


def disconnect_last_connected_unit(unit):
    # check the connection type of the last connected unit
    connection_to_the_next_unit = unit['ConnectionToNextRadio']
    command = unit['ProtectionCommand']
    last_connected_ip = unit['IP']

    if connection_to_the_next_unit == 'rf':
        send_slack_message(f'Connection to the next unit is RF. Need to turn on ALIGNMENT of {last_connected_ip}')
    else:
        send_slack_message(
            f'Connection to the next unit is Ethernet. Need to turn down {connection_to_the_next_unit} of {last_connected_ip}')

    send_slack_message(f'Executing: {command}')
    odu = SikluUnit(unit['IP'], unit['Username'], unit['Password'], debug=False)
    odu.connect()
    if odu.connected:
        status = odu.send_command(unit['ProtectionCommand'])
        odu.send_command('copy running-configuration startup-configuration')
    else:
        send_slack_message(f"Failed to connect to {unit['IP']}")
        return False

    return status


def is_rf_up(unit, timeout):
    odu = SikluUnit(unit['IP'], unit['Username'], unit['Password'], debug=False)
    odu.connect()
    send_slack_message(f'Waiting for RF to come up...')
    connection_timeout = time.time() + timeout
    while time.time() <= connection_timeout:
        if ShowRFStatus(odu).parse()[0] == 'up':
            return True
        time.sleep(1)
    return False


class SikluUnitClearedFDB(SikluUnit):
    fdb_cleared = False

    def connect(self):
        if self.connected:
            return
        SikluUnit.connect(self)
        self.fdb_cleared = False

    def clear_fdb(self):
        self.connect()
        if self.connected and not self.fdb_cleared:
            self.send_command('clear fdb-table all all')
            self.fdb_cleared = True


def wait_for_connectivity(ips_to_ping, units_in_ring, timeout):
    send_slack_message(f'Waiting for connectivity...')
    odus = {}
    for i, unit in units_in_ring[units_in_ring['IP'].isin(ips_to_ping)].iterrows():
        odus[unit['IP']] = SikluUnitClearedFDB(unit['IP'], unit['Username'], unit['Password'], debug=False)

    connection_timeout = time.time() + timeout
    while time.time() <= connection_timeout:
        send_slack_message('Pinging IPs:')
        send_slack_message(",".join(ips_to_ping))

        ping_results = ping_all_units(ips_to_ping)
        all_alive = sum([is_alive for ip, is_alive in ping_results]) == len(ips_to_ping)
        if all_alive:
            return results

        not_connected_ips = [ip for ip, is_alive in ping_results if not is_alive]
        send_slack_message('Not connected IPs:')
        send_slack_message(",".join(not_connected_ips))

        # clear FDB table of connected units
        for ip, is_alive in ping_results:
            if is_alive:
                odus[ip].clear_fdb()

    return results


if __name__ == "__main__":
    units_in_ring = pd.read_csv(UNITS_FILENAME)

    ips_to_ping = units_in_ring[units_in_ring['Type'] == 'BH']['IP'].tolist()
    cw_ips = units_in_ring[(units_in_ring['Type'] == 'BH') & (units_in_ring['Direction'] == 'CW')]['IP'].tolist()
    acw_ips = units_in_ring[(units_in_ring['Type'] == 'BH') & (units_in_ring['Direction'] == 'ACW')]['IP'].tolist()

    # save running configuration to startup configuration
    for i, unit in units_in_ring[units_in_ring['IP'].isin(ips_to_ping)].iterrows():
        save_running_config(unit)

    execution_counter = 0

    send_slack_message('Pinging units...')

    while True:
        execution_counter += 1
        # send_slack_message('Pinging units...')
        results = ping_all_units(ips_to_ping)
        all_alive = sum([is_alive for ip, is_alive in results]) == len(ips_to_ping)

        # all units are connected
        if all_alive:
            if (execution_counter * DELAY_BETWEEN_PING_TEST_SEC) % KEEP_ALIVE_SEC == 0:
                # send message every hour
                send_slack_message(f'All units alive. Sleeping for {DELAY_BETWEEN_PING_TEST_SEC} seconds.')
            time.sleep(DELAY_BETWEEN_PING_TEST_SEC)
            continue

        # we have a connectivity event
        else:
            send_slack_message('At least one unit is disconnected!')
            # at least one IP is not connected
            # wait until there are N_CONSECUTIVE_PINGS_LOST
            for i in range(N_CONSECUTIVE_PINGS_LOST):
                # send_slack_message(f'Checking ping {i + 1}')
                results = ping_all_units(ips_to_ping)
                all_alive = sum([is_alive for ip, is_alive in results]) == len(ips_to_ping)
                if all_alive:
                    break

            # all units are back again
            if all_alive:
                send_slack_message('All units reconnected. Back to normal.')
                continue

            # we have a disconnection event!
            send_slack_message(f'{N_CONSECUTIVE_PINGS_LOST} consecutive pings lost. Need to activate RPL.')
            not_connected_ips = [ip for ip, is_alive in results if not is_alive]
            send_slack_message('Not connected IPs:')
            send_slack_message(",".join(not_connected_ips))

            # check the unconnected side
            if (units_in_ring[units_in_ring["IP"].isin(not_connected_ips)]["Direction"] == 'CW').all():
                unconnected_direction = 'CW'
                # if the disconnect is on the CW side, the RPL should be activated on the ACW side
                rpl_side = 'ACW'
                first_unconnected_ip = find_first_unconnected_ip(not_connected_ips, cw_ips)
                # if the first unit is unconnected, break
                if first_unconnected_ip == cw_ips[0]:
                    send_slack_message(f'First unit is unreachable. PoP failure. Exiting...')
                    break
                last_connected_ip = find_last_connected_ip(first_unconnected_ip, cw_ips)
            elif (units_in_ring[units_in_ring["IP"].isin(not_connected_ips)]["Direction"] == 'ACW').all():
                unconnected_direction = 'ACW'
                # if the disconnect is on the ACW side, the RPL should be activated on the CW side
                rpl_side = 'CW'
                first_unconnected_ip = find_first_unconnected_ip(not_connected_ips, acw_ips)
                if first_unconnected_ip == acw_ips[0]:
                    send_slack_message(f'First unit is unreachable. PoP failure. Exiting...')
                    break
                last_connected_ip = find_last_connected_ip(first_unconnected_ip, acw_ips)
            else:
                send_slack_message(f'Units disconnected on both directions. Exiting...')
                break

            send_slack_message(f'Unconnected direction: {unconnected_direction}')
            send_slack_message(f'First unconnected IP: {first_unconnected_ip}')

            # disconnect the last connected unit
            disconnect_last_connected_unit(units_in_ring[units_in_ring["IP"] == last_connected_ip].squeeze())

            # activate RPL
            rpl_activation_unit = units_in_ring[
                (units_in_ring["ConnectionToNextRadio"] == 'rpl') &
                (units_in_ring["Direction"] == rpl_side)
            ].squeeze()
            activate_rpl(rpl_activation_unit)

            # wait for RF to come up
            if not is_rf_up(rpl_activation_unit, WAIT_FOR_RF_SEC):
                send_slack_message('RPL is not coming up. Exiting...')
                break

            # wait for Ethernet connectivity
            results = wait_for_connectivity(ips_to_ping, units_in_ring, WAIT_FOR_AGING_SEC)
            all_alive = sum([is_alive for ip, is_alive in results]) == len(ips_to_ping)

            if all_alive:
                send_slack_message('All units alive.')
            else:
                not_connected_ips = [ip for ip, is_alive in results if not is_alive]
                send_slack_message('Not connected IPs:')
                send_slack_message(",".join(not_connected_ips))

            send_slack_message('RPL is up.')

            # exit if a fault was detected
            if EXIT_ON_FAULT:
                send_slack_message('Exiting...')
                break
