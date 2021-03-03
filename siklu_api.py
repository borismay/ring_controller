from __future__ import print_function

import collections
import os
import pandas as pd
import platform
import re
import sys
import sys
import time
from multiprocessing import Pool
from subprocess import call

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser  # ver. < 3.0

try:
    import wexpect

    TIMEOUT = wexpect.TIMEOUT
    EOF = wexpect.EOF
except:
    import pexpect

    TIMEOUT = pexpect.TIMEOUT
    EOF = pexpect.EOF

from datetime import datetime, timedelta


############################################################################

class SikluUnit:
    def __init__(self, host, username, password, port='22', connection_timeout=12, debug=True):
        self.host = host
        self.user = username
        self.passwd = password
        self.port = port
        self.connection_timeout = connection_timeout
        self.debug = debug
        self.prompt = '~ #'
        self.prompt2 = ">$"

        self.connected = False
        self.connection = None

        # if platform.system() == 'Windows':
        #     self.sshask_newkey = 'Store key in cache?'
        #     self.sshask_newkey_answer = 'y'
        # else:
        self.sshask_newkey = 'Are you sure you want to continue connecting'
        self.sshask_newkey_answer = 'yes'

        self.sshask_passwd = self.user + "@" + self.host + "'s password: "
        self.noroutehost = 'No route to host'
        self.exit = 'exit'

    def disconnect(self):
        if self.connected:
            self.connection.sendline(self.exit)
            self.connection.expect(EOF)
            self.connected = False
            self.connection = None

    def __del__(self):
        self.disconnect()

    def connect(self):
        # renew SSH key
        # ssh - keygen - f  "/root/.ssh/known_hosts" - R 172.20.4.6
        if self.connected:
            self.disconnect()

        kiss = True

        try:
            if platform.system() == 'Windows':
                foo = wexpect.spawn(r'ssh %s@%s' % (self.user, self.host))
            else:  # assume linux
                foo = pexpect.spawn('ssh %s@%s' % (self.user, self.host))

            i = foo.expect([TIMEOUT, self.sshask_newkey, self.sshask_passwd, self.noroutehost], timeout=self.connection_timeout)

            if i == 0:  ## Timeout
                if debug:
                    print("[%s] Connection timeout" % self.host)
                kiss = False
            if i == 1:  ## lors de la premiere connexion
                foo.sendline(self.sshask_newkey_answer)
                j = foo.expect([TIMEOUT, self.sshask_passwd])
                if j == 0:
                    if debug:
                        print("[%s] Password incorrect" % self.host)
                    kiss = False
            if i == 3:
                if self.debug:
                    print("[%s] No route to host" % self.host)
                kiss = False
            if kiss:
                foo.sendline(self.passwd)
                foo.expect(self.prompt2)
                self.connection = foo
                self.connected = True
                if self.debug:
                    print("[%s] Connected successfully" % self.host)
        except Exception as e:
            if self.debug:
                print(e)
                print("[%s] Unexpected error: %s" % (self.host, foo.before))

    def send_command(self, command, no_wait=False):
        if self.debug:
            print('[%s] %s' % (self.host, command))
        self.connection.sendline(command)
        if no_wait:
            return

        self.connection.expect(self.prompt2)
        try:
            return self.connection.before.decode('utf-8')
        except:
            return self.connection.before


#######################################################################################
class SikluCommandParam:
    def __init__(self, name='', value='', regex=r'', format_func=None):
        self.name = name
        self.value = value
        self.regex = regex
        self.format_func = format_func


class SikluCommandParserBase:
    cmd = ''
    cmd_params = [SikluCommandParam()]
    reverse_reply = False
    multiline = False

    def __init__(self, connection=None):
        self.connection = connection

    def parse(self):
        if self.connection:
            self.reply = self.connection.send_command(self.cmd)
            if self.reverse_reply:
                lines = self.reply.split("\r\n")
                lines.reverse()
                self.reply = r"\r\n".join(lines)
        else:
            self.reply = ''
        return self.parse_reply()

    def parse_reply(self):
        for param in self.cmd_params:
            if param.regex:
                if param.format_func:
                    param.value = param.format_func(self, self.find_value(param.regex, self.reply))
                else:
                    param.value = self.find_value(param.regex, self.reply)

        return [param.value for param in self.cmd_params]

    def find_value(self, regex, text):
        if self.multiline:
            r = re.search(regex, text, re.MULTILINE)
        else:
            r = re.search(regex, text)
        if r:
            s = r.groups()[0].strip().replace(',', '')
            return s
        else:
            return []

    def __str__(self):
        return ','.join(param.name for param in self.cmd_params)

    def set_connection(self, connection):
        self.connection = connection


#######################################################################################
class ShowSystem(SikluCommandParserBase):
    cmd = 'show system'

    def format_days_up_time(self, time_str):
        return int(time_str.split(':')[0])

    cmd_params = [SikluCommandParam('system_description', '', r"system description\s+: (.+)\n"),
                  SikluCommandParam('system_name', '', r"system name\s+: (.+)\n"),
                  SikluCommandParam('system_location', '', r"system location\s+: (.+)\n"),
                  SikluCommandParam('system_up_days', '', r"system uptime\s+: (.+)\n", format_days_up_time),
                  SikluCommandParam('system_time', '', r"system time\s+: (.+)\n"),
                  SikluCommandParam('system_date', '', r"system date\s+: (.+)\n"),
                  SikluCommandParam('system_temp', '', r"system temperature\s+: (.+)\n"),
                  SikluCommandParam('queue_early_discard', '', r"system queue-early-discard\s+: (.+)\n"),
                  ]


class ShowInventory(SikluCommandParserBase):
    cmd = 'show inventory 1 serial'
    cmd_params = [SikluCommandParam('system_sn', '', r"inventory 1 serial\s+: (.+)\n"), ]


class ShowNTP(SikluCommandParserBase):
    cmd = 'show ntp'
    cmd_params = [
        SikluCommandParam('ntp_1_server', '', r"ntp 1 server\s+: (.+)\n"),
        SikluCommandParam('ntp_1_tmz', '', r"ntp 1 tmz\s+: (.+)\n"),
    ]


class ShowSNMPManager(SikluCommandParserBase):
    cmd = 'show snmp-mng'
    cmd_params = [
        SikluCommandParam('snmp_mng_1_ip_addr', '', r"snmp-mng 1 ip-addr\s+: (.+)\n"),
        SikluCommandParam('snmp_mng_1_sec_name', '', r"snmp-mng 1 security-name\s+: (.+)\n"),
    ]


class ShowSNMPAgent(SikluCommandParserBase):
    cmd = 'show snmp-agent'
    cmd_params = [
        SikluCommandParam('snmp_agent_read_com', '', r"snmp-agent read-com\s+: (.+)\n"),
        SikluCommandParam('snmp_agent_write_com', '', r"snmp-agent write-com\s+: (.+)\n"),
    ]


class ShowSyslog(SikluCommandParserBase):
    cmd = 'show syslog'
    cmd_params = [
        SikluCommandParam('syslog_1_server', '', r"syslog 1 server\s+: (.+)\n"),
    ]


class LastLogEvents(SikluCommandParserBase):
    cmd = 'show log'
    reverse_reply = True
    multiline = True
    cmd_params = [SikluCommandParam('last rf reset', '', r"([A-Z]{1}[a-z]{2}[0-9:\s]+) sw cad: link down eth eth0"),
                  SikluCommandParam('last system reset', '', r"([A-Z]{1}[a-z]{2}[0-9:\s]+) sw bspd: \*\*\* Reset"),
                  ]
    # def parse_reply(self):
    #     pass


class ShowSW(SikluCommandParserBase):
    cmd = 'show sw'
    cmd_params = [SikluCommandParam('bank', '1', ''),
                  SikluCommandParam('b1_ver', '', r"1\s+[MH-]*?([\.0123456789]+)\s+"),
                  # SikluCommandParam('b1_date', '', r"1\s+[MH-]*?[\.0123456789]+\s+([\-0123456789]+)\s+"),
                  # SikluCommandParam('b1_time', '', r"1\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+([\:0123456789]+)\s+"),
                  SikluCommandParam('b1_running', '',
                                    r"1\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+[\:0123456789]+\s+([\w-]+)\s+"),
                  SikluCommandParam('b1_scheduled_to_run', '',
                                    r"1\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+[\:0123456789]+\s+[\w-]+\s+([\w]+)\s+"),
                  SikluCommandParam('b1_startup', '',
                                    r"1\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+[\:0123456789]+\s+[\w-]+\s+[\w]+\s+([\w]+)"),
                  SikluCommandParam('bank', '2', ''),
                  SikluCommandParam('b2_ver', '', r"2\s+[MH-]*?([\.0123456789]+)\s+"),
                  # SikluCommandParam('b2_date', '', r"2\s+[MH-]*?[\.0123456789]+\s+([\-0123456789]+)\s+"),
                  # SikluCommandParam('b2_time', '', r"2\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+([\:0123456789]+)\s+"),
                  SikluCommandParam('b2_running', '',
                                    r"2\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+[\:0123456789]+\s+([\w-]+)\s+"),
                  SikluCommandParam('b2_scheduled_to_run', '',
                                    r"2\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+[\:0123456789]+\s+[\w-]+\s+([\w]+)\s+"),
                  SikluCommandParam('b2_startup', '',
                                    r"2\s+[MH-]*?[\.0123456789]+\s+[\-0123456789]+\s+[\:0123456789]+\s+[\w-]+\s+[\w]+\s+([\w]+)"),
                  ]


class ShowRF(SikluCommandParserBase):
    cmd = 'show rf'
    cmd_params = [SikluCommandParam('rf_operational', '', r"rf operational\s+: (.+)\n"),
                  SikluCommandParam('rf_cinr', '', r"rf cinr\s+: (.+)\n"),
                  SikluCommandParam('rf_rssi', '', r"rf rssi\s+: (.+)\n"),
                  SikluCommandParam('rf_frequency', '', r"rf [tx-]*?frequency\s+: (.+)\n"),
                  SikluCommandParam('rf_mode', '', r"rf mode\s+: (.+)\n"),
                  SikluCommandParam('rf_role', '', r"rf role\s+: (.+)\n"),
                  SikluCommandParam('rf_tx_asymmetry', '', r"rf tx-asymmetry\s+: (.+)\n"),
                  ]


class ShowRFStatus(SikluCommandParserBase):
    cmd = 'show rf operational'
    cmd_params = [SikluCommandParam('rf_operational', '', r"rf operational\s+: (.+)\n"),
                  ]


class ShowRFDebug(SikluCommandParserBase):
    cmd = 'show rf-debug'
    cmd_params = [SikluCommandParam('cinr_low', '', r"rf-debug cinr-low\s+: (.+)\n"),
                  SikluCommandParam('link_length', '', r"rf-debug link-length\s+: (.+)\n"),
                  SikluCommandParam('tx_temp', '', r"rf-debug tx-temperature\s+: (.+)\n"),
                  SikluCommandParam('rx_temp', '', r"rf-debug rx-temperature\s+: (.+)\n"),
                  ]


class ShowRSSI(SikluCommandParserBase):
    cmd = 'show rf rssi'
    cmd_params = [SikluCommandParam('rf_rssi', '', r"rf rssi\s+: (.+)\n"),
                  ]


class ShowLicense(SikluCommandParserBase):
    cmd = 'show license'
    cmd_params = [SikluCommandParam('data_rate_status', '', r"license\s+data-rate\s+status\s+:\s+(.+)\n"),
                  SikluCommandParam('data_rate_permission', '', r"license\s+data-rate\s+permission\s+:\s+(.+)\n"),
                  ]


class ShowRing(SikluCommandParserBase):

    def __init__(self, connection=None, ring_num=1):
        SikluCommandParserBase.__init__(self, connection)
        self.ring_num = ring_num
        self.cmd = 'show ring %d' % self.ring_num
        self.cmd_params = [SikluCommandParam('ring_number', self.ring_num, ''),
                           SikluCommandParam('ring-id', '', r"ring \d ring-id\s+: (.+)\n"),
                           SikluCommandParam('type', '', r"ring \d type\s+: (.+)\n"),
                           SikluCommandParam('role', '', r"ring \d role\s+: (.+)\n"),
                           SikluCommandParam('parent-ring', '', r"ring \d parent-ring\s+: (.+)\n"),
                           SikluCommandParam('cw-port', '', r"ring \d cw-port\s+: (.+)\n"),
                           SikluCommandParam('acw-port', '', r"ring \d acw-port\s+: (.+)\n"),
                           SikluCommandParam('raps-cvid', '', r"ring \d raps-cvid\s+: (.+)\n"),
                           SikluCommandParam('state', '', r"ring \d state\s+: (.+)\n"),
                           SikluCommandParam('last-state-time', '', r"ring \d last-state-time\s+: (.+)\n"),
                           SikluCommandParam('cw-status-data', '', r"ring \d cw-status-data\s+: (.+)\n"),
                           SikluCommandParam('acw-status-data', '', r"ring \d acw-status-data\s+: (.+)\n"),
                           SikluCommandParam('cw-status-raps', '', r"ring \d cw-status-raps\s+: (.+)\n"),
                           SikluCommandParam('acw-status-raps', '', r"ring \d acw-status-raps\s+: (.+)\n"),
                           ]


class ShowMngVLAN(SikluCommandParserBase):
    cmd = 'show bridge-port c3 eth1 pvid'
    cmd_params = [SikluCommandParam('eth1_pvid', '', r"bridge-port c3 eth1 pvid\s+: (.+)\n"),
                  ]


class ShowEth1(SikluCommandParserBase):
    cmd = 'show eth eth1 eth-act-type'
    cmd_params = [SikluCommandParam('eth1_act_type', '', r"eth eth1 eth-act-type\s+: (.+)\n"),
                  ]


class ShowEth2(SikluCommandParserBase):
    cmd = 'show eth eth2 eth-act-type'
    cmd_params = [SikluCommandParam('eth2_act_type', '', r"eth eth2 eth-act-type\s+: (.+)\n"),
                  ]


class ShowEth3(SikluCommandParserBase):
    cmd = 'show eth eth3 eth-act-type'
    cmd_params = [SikluCommandParam('eth3_act_type', '', r"eth eth3 eth-act-type\s+: (.+)\n"),
                  ]


class ShowBU(SikluCommandParserBase):
    cmd = 'show base-unit'
    cmd_params = [SikluCommandParam('self_mac', '', r"base-unit self-mac\s+: (.+)\n"),
                  SikluCommandParam('ssid', '', r"base-unit ssid\s+: (.+)\n"),
                  SikluCommandParam('password', '', r"base-unit password\s+: (.+)\n"),
                  SikluCommandParam('frequency', '', r"base-unit frequency\s+: (.+)\n"),
                  ]


class ShowTU(SikluCommandParserBase):
    cmd = 'show terminal-unit'
    cmd_params = [SikluCommandParam('self_mac', '', r"terminal-unit self-mac\s+: (.+)\n"),
                  SikluCommandParam('bu_mac', '', r"terminal-unit base-unit-mac\s+: (.+)\n"),
                  SikluCommandParam('ssid', '', r"terminal-unit ssid\s+: (.+)\n"),
                  SikluCommandParam('password', '', r"terminal-unit password\s+: (.+)\n"),
                  SikluCommandParam('frequency', '', r"terminal-unit frequency\s+: (.+)\n"),
                  SikluCommandParam('tx_mcs', '', r"terminal-unit tx-mcs\s+: (.+)\n"),
                  SikluCommandParam('rssi', '', r"terminal-unit rssi\s+: (.+)\n"),
                  SikluCommandParam('signal_quality', '', r"terminal-unit signal-quality\s+: (.+)\n"),
                  SikluCommandParam('connect_time', '', r"terminal-unit connect-time\s+: (.+)\n"),
                  ]


class ShowRemoteTU(SikluCommandParserBase):
    cmd = 'show remote-terminal-unit'

    def __init__(self, connection=None):
        SikluCommandParserBase.__init__(self, connection)
        self.cmd_params = [item for sublist in [self.gen_cmd_params(tu_num) for tu_num in range(1, 9)] for item in
                           sublist]

    def gen_cmd_params(self, tu_num):
        return [SikluCommandParam('tu_num_%d' % tu_num, tu_num, r""),
                SikluCommandParam('eth_port_%d' % tu_num, '', r"remote-terminal-unit %d eth-port\s+: (.+)\n" % tu_num),
                SikluCommandParam('mac_%d' % tu_num, '', r"remote-terminal-unit %d mac\s+: (.+)\n" % tu_num),
                SikluCommandParam('name_%d' % tu_num, '', r"remote-terminal-unit %d name\s+: (.+)\n" % tu_num),
                SikluCommandParam('status_%d' % tu_num, '', r"remote-terminal-unit %d status\s+: (.+)\n" % tu_num),
                SikluCommandParam('tx_mcs_%d' % tu_num, '', r"remote-terminal-unit %d tx-mcs\s+: (.+)\n" % tu_num),
                SikluCommandParam('rssi_%d' % tu_num, '', r"remote-terminal-unit %d rssi\s+: (.+)\n" % tu_num),
                SikluCommandParam('signal_quality_%d' % tu_num, '',
                                  r"remote-terminal-unit %d signal-quality\s+: (.+)\n" % tu_num),
                SikluCommandParam('tx_sector_%d' % tu_num, '',
                                  r"remote-terminal-unit %d tx-sector\s+: (.+)\n" % tu_num),
                SikluCommandParam('rem_tx_sector_%d' % tu_num, '',
                                  r"remote-terminal-unit %d rem-tx-sector\s+: (.+)\n" % tu_num),
                ]


class ShowLLDPRemote(SikluCommandParserBase):
    cmd = 'show lldp-remote'

    def __init__(self, connection=None):
        SikluCommandParserBase.__init__(self, connection)
        self.cmd_params = [item for sublist in [self.gen_cmd_params(eth_num) for eth_num in range(0, 5)] for item in
                           sublist]

    def gen_cmd_params(self, eth_num):
        return [
            SikluCommandParam('chassis_id_%d' % eth_num, '',
                              r"lldp-remote eth%d [\d]{1} chassis-id\s+: (.+)\n" % eth_num),
            SikluCommandParam('port_descr_%d' % eth_num, '',
                              r"lldp-remote eth%d [\d]{1} port-descr\s+: (.+)\n" % eth_num),
            SikluCommandParam('sys_name_%d' % eth_num, '', r"lldp-remote eth%d [\d]{1} sys-name\s+: (.+)\n" % eth_num),
            SikluCommandParam('sys_descr_%d' % eth_num, '',
                              r"lldp-remote eth%d [\d]{1} sys-descr\s+: (.+)\n" % eth_num),
        ]


class ShowRfStatisticsDaily(SikluCommandParserBase):
    cmd = 'show rf statistics-summary-days'
    multiline = True

    def __init__(self, connection=None):
        SikluCommandParserBase.__init__(self, connection)
        self.cmd_params = [item for sublist in [self.gen_cmd_params(day) for day in range(0, 32)] for item in sublist]

    def gen_cmd_params(self, day):
        return [
            # SikluCommandParam('date_%d' % eth_num, '', r"lldp-remote eth%d [\d]{1} chassis-id\s+: (.+)\n" % eth_num),
            # SikluCommandParam('min_rssi_%d' % eth_num, '', r"lldp-remote eth%d [\d]{1} port-descr\s+: (.+)\n" % eth_num),
            # SikluCommandParam('min_cinr_%d' % eth_num, '', r"lldp-remote eth%d [\d]{1} sys-name\s+: (.+)\n" % eth_num),
            SikluCommandParam('min_mod_%d' % day, '',
                              r"^%d\s+[\.\d]+\s+[:\d]+\s+[-\d]+\s+[-\d]+\s+[-\d]+\s+[-\d]+\s+([\w\d]+)\s+[\w\d]+\s+[yesno]+" % day),
        ]


class ShowRfStatisticsSummary(SikluCommandParserBase):
    multiline = True
    columns = ['interval', 'start_ts', 'min-rssi', 'max-rssi', 'min-cinr', 'max-cinr', 'min-mod', 'max-mod']

    def __init__(self, connection=None):
        self.cmd = 'show rf statistics-summary'
        SikluCommandParserBase.__init__(self, connection)
        self.cmd_params = [item for sublist in [self.gen_cmd_params(time_interval) for time_interval in range(0, 96)]
                           for item in sublist]

    def gen_cmd_params(self, time_interval):
        return [
            SikluCommandParam('record_%d' % time_interval, '',
                              r"^(%d\s+[\.\d]+\s+[:\d]+\s+[-\d]+\s+[-\d]+\s+[-\d]+\s+[-\d]+\s+[\w\d\s\.]+\s{2,}[\w\d\s\.]+\s{2,}[yesnounknown]+)" % time_interval),
        ]

    def parse_reply(self):
        stats = []
        for param in self.cmd_params:
            interval_values = self.find_value(param.regex, self.reply)
            # import pdb; pdb.set_trace()
            if interval_values:
                r = re.search(
                    r"(\d+)\s+([\.\d]+\s+[:\d]+)\s+([-\d]+)\s+([-\d]+)\s+([-\d]+)\s+([-\d]+)\s+([\w\d\s\.]+)\s{2,}([\w\d\s\.]+)",
                    interval_values)
                if r:
                    r = r.groups()
                    stats.append(
                        [int(r[0]), datetime.strptime(r[1], '%Y.%m.%d %H:%M:%S'), int(r[2]), int(r[3]), int(r[4]),
                         int(r[5]), r[6], r[7]])
                else:
                    continue

        return pd.DataFrame(stats, columns=self.columns)

    def __str__(self):
        return ','.join(self.columns)


class ShowRfStatisticsSummaryLast(SikluCommandParserBase):
    columns = ['valid_line', 'min-rssi', 'min-cinr', 'min-mod']
    multiline = True

    def __init__(self, connection=None):
        self.cmd = 'show rf statistics-summary'
        SikluCommandParserBase.__init__(self, connection)
        self.cmd_params = [item for sublist in
                           [self.gen_cmd_params(time_interval) for time_interval in range(95, -1, -1)] for item in
                           sublist]

    def gen_cmd_params(self, time_interval):
        return [
            SikluCommandParam('record_%d' % time_interval, '',
                              r"^(%d\s+[\.\d]+\s+[:\d]+\s+[-\d]+\s+[-\d]+\s+[-\d]+\s+[-\d]+\s+[\w\d]+\s+[\w\d]+\s+[yesno]+)" % time_interval),
        ]

    def parse_reply(self):
        valid_line = 95
        for param in self.cmd_params:
            interval_values = self.find_value(param.regex, self.reply)
            # import pdb; pdb.set_trace()
            if interval_values:
                r = re.search(
                    r"(\d+)\s+([\.\d]+\s+[:\d]+)\s+([-\d]+)\s+([-\d]+)\s+([-\d]+)\s+([-\d]+)\s+([\w\d]+)\s+([\w\d]+)",
                    interval_values)
                if r:
                    r = r.groups()
                    if int(r[0]) == valid_line:
                        return [int(r[0]), int(r[2]), int(r[4]), r[6]]
                    else:
                        valid_line = int(r[0]) - 1
                else:
                    continue

        return ["", "", "", ""]

    def __str__(self):
        return ','.join(self.columns)


class ShowEthStatisticsSummary(SikluCommandParserBase):
    multiline = True
    columns = ['interval', 'start_ts', 'interface', 'in-octets', 'out-octets', 'in-rate', 'out-rate', 'util']

    def __init__(self, connection=None, eth='eth1'):
        self.cmd = 'show eth %s statistics-summary' % eth
        SikluCommandParserBase.__init__(self, connection)
        self.cmd_params = [item for sublist in [self.gen_cmd_params(time_interval) for time_interval in range(0, 96)]
                           for item in sublist]

    def gen_cmd_params(self, time_interval):
        return [
            SikluCommandParam('record_%d' % time_interval, '',
                              r"^(%d\s+[\.\d]+\s+[:\d]+\s+eth\d\s+[\d]+\s+[\d]+\s+[\d]+\s+[\d]+\s+[\d]+)" % time_interval),
        ]

    def parse_reply(self):
        stats = []
        # print self.reply
        for param in self.cmd_params:
            interval_values = self.find_value(param.regex, self.reply)
            # print param.regex
            # import pdb; pdb.set_trace()
            if interval_values:
                r = re.search(
                    r"(\d+)\s+([\.\d]+\s+[:\d]+)\s+(eth[\d])\s+([\d]+)\s+([\d]+)\s+([\d]+)\s+([\d]+)\s+([\d]+)",
                    interval_values)
                if r:
                    r = r.groups()
                    stats.append(
                        [int(r[0]), datetime.strptime(r[1], '%Y.%m.%d %H:%M:%S'), r[2], int(r[3]), int(r[4]), int(r[5]),
                         int(r[6]), int(r[7])])
                else:
                    continue

        return pd.DataFrame(stats, columns=self.columns)

    def __str__(self):
        return ','.join(self.columns)


#######################################################################################
def scan_unit(unit, commands):
    status = [unit.host, 'scan', True]

    for command in commands:
        command.set_connection(unit)
        status += command.parse()

    return status


def copy_sw_unit(unit, command):
    try:
        status = unit.send_command(command.replace('upload_sw', 'copy'), no_wait=True)
        status = [unit.host, 'copy', True]
    except Exception as e:
        print(e)
        status = [unit.host, 'copy', False, str(e)]

    return status


def run_sw_unit(unit, accept_timeout=600, rollback_timeout=600):
    try:
        status = unit.send_command('copy running-configuration startup-configuration')
        status = unit.send_command('run sw next-rst %d' % accept_timeout)
        status = unit.send_command('set rollback timeout %d' % rollback_timeout)
        status = [unit.host, 'run_sw', True]
    except Exception as e:
        print(e)
        status = [unit.host, 'run_sw', False, str(e)]

    return status


def accept_unit(unit):
    try:
        status = unit.send_command('accept sw')
        status = [unit.host, 'accept', True]
    except Exception as e:
        print(e)
        status = [unit.host, 'accept', False, str(e)]

    return status


def copy_script_unit(unit, command):
    try:
        status = unit.send_command(command.replace('upload_script', 'copy'), no_wait=True)
        status = [unit.host, 'upload_script', True]
    except Exception as e:
        print(e)
        status = [unit.host, 'upload_script', False, str(e)]
    return status


def run_script_unit(unit, command):
    try:
        status = unit.send_command(command.replace('run_script', 'run'), no_wait=True)
        status = [unit.host, 'run_script', True]
    except Exception as e:
        print(e)
        status = [unit.host, 'run_script', False, str(e)]

    return status


def run_command_unit(unit, command):
    try:
        status = unit.send_command(command.replace('run_command ', ''), no_wait=True)
        status = [unit.host, 'run_command', True]
    except Exception as e:
        print(e)
        status = [unit.host, 'run_command', False, str(e)]

    return status


##############################################################################
def run_command(unit_):
    unit = unit_['unit']
    command = unit_['command']

    if not unit.connected:
        unit.connect()

    if unit.connected:
        if command.startswith('upload_sw'):
            status = copy_sw_unit(unit, command)
        elif command.startswith('run_sw'):
            status = run_sw_unit(unit, accept_timeout=600, rollback_timeout=600)
        elif command.startswith('accept'):
            status = accept_unit(unit)
        elif command.startswith('scan'):
            commands = unit_['scan_commands']
            status = scan_unit(unit, commands)
        elif command.startswith('upload_script'):
            status = copy_script_unit(unit, command)
        elif command.startswith('run_script'):
            status = run_script_unit(unit, command)
        elif command.startswith('run_command'):
            status = run_command_unit(unit, command)
        else:
            status = [unit.host, command, False, 'Invalid command']
    else:
        status = [unit.host, 'scan', False, 'No connection']

    ts = time.strftime('%d-%m-%Y %H:%M:%S', time.localtime())
    s = ','.join([ts] + [str(x) for x in status])
    return s


def units_manager_parallel(hosts, RINGS=3, MH_ENABLED=False, N_PROCESSES=10):
    units = []

    # add scan commands here
    scan_commands = [ShowInventory(), ShowSystem(), ShowNTP(),
                     ShowSyslog(), ShowSNMPManager(), ShowSNMPAgent(),
                     ShowRfStatisticsSummaryLast(),
                     ShowSW(), ShowRF(), ShowRFDebug(), ShowLicense(),
                     ShowMngVLAN(), ShowEth1(), ShowEth2(), ShowEth3(), ShowLLDPRemote()] \
                    + [ShowRing(ring_num=n + 1) for n in range(RINGS)] \
                    + [ShowRfStatisticsDaily(), ]

    if MH_ENABLED:
        scan_commands += [ShowBU(), ShowTU(), ShowRemoteTU()]

    for i, host in hosts.iterrows():
        unit = SikluUnit(host['ip'], host['user'], host['password'])
        units.append({'unit': unit, 'command': host['command'], 'scan_commands': scan_commands})

    ts = time.strftime('%d%m%Y_%H%M', time.localtime())
    filename = 'execution_log_%s.csv' % ts

    file_header = 'time_stamp,host,command,command_status,' + ','.join(str(command) for command in scan_commands) + '\n'

    pool = Pool(processes=N_PROCESSES)
    replies = pool.map(run_command, units)
    pool.close()
    pool.join()

    fid = open(filename, 'w')
    fid.write(file_header)
    fid.write('\n'.join(replies))
    return filename
