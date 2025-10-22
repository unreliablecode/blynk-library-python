# Copyright (c) 2015-2019 Volodymyr Shymanskyy. See the file LICENSE for copying permission.

__version__ = "1.0.0"

import struct
import time
import sys
import os

try:
    import machine
    gettime = lambda: time.ticks_ms()
    SOCK_TIMEOUT = 0
except ImportError:
    const = lambda x: x
    gettime = lambda: int(time.time() * 1000)
    SOCK_TIMEOUT = 0.05

def dummy(*args):
    pass

MSG_RSP = const(0)
MSG_LOGIN = const(2)
MSG_PING  = const(6)

MSG_TWEET = const(12)
MSG_NOTIFY = const(14)
MSG_BRIDGE = const(15)
MSG_HW_SYNC = const(16)
MSG_INTERNAL = const(17)
MSG_PROPERTY = const(19)
MSG_HW = const(20)
MSG_HW_LOGIN = const(29)
MSG_EVENT_LOG = const(64)

MSG_REDIRECT  = const(41)  # TODO: not implemented
MSG_DBG_PRINT  = const(55) # TODO: not implemented

STA_SUCCESS = const(200)
STA_INVALID_TOKEN = const(9)

DISCONNECTED = const(0)
CONNECTING = const(1)
CONNECTED = const(2)

print("""
    ___  __          __
   / _ )/ /_ _____  / /__
  / _  / / // / _ \\/  '_/
 /____/_/\\_, /_//_/_/\\_\\
        /___/ for Python v""" + __version__ + " (" + sys.platform + ")\n")

class EventEmitter:
    def __init__(self):
        self._cbks = {}

    def on(self, evt, f=None):
        if f:
            self._cbks[evt] = f
        else:
            def D(f):
                self._cbks[evt] = f
                return f
            return D

    def emit(self, evt, *a, **kv):
        if evt in self._cbks:
            self._cbks[evt](*a, **kv)


class BlynkProtocol(EventEmitter):
    def __init__(self, auth, tmpl_id=None, fw_ver=None, heartbeat=50, buffin=1024, log=None):
        EventEmitter.__init__(self)
        self.heartbeat = heartbeat*1000
        self.buffin = buffin
        self.log = log or print # Changed default to print for better debugging
        self.auth = auth
        self.tmpl_id = tmpl_id
        self.fw_ver = fw_ver
        self.state = DISCONNECTED
        self.conn = None # Add conn attribute to base class
        self.connect()

    def virtual_write(self, pin, *val):
        self._send(MSG_HW, 'vw', pin, *val)

    def send_internal(self, pin, *val):
        self._send(MSG_INTERNAL,  pin, *val)

    def set_property(self, pin, prop, *val):
        self._send(MSG_PROPERTY, pin, prop, *val)

    def sync_virtual(self, *pins):
        self._send(MSG_HW_SYNC, 'vr', *pins)

    def log_event(self, *val):
        self._send(MSG_EVENT_LOG, *val)

    def _send(self, cmd, *args, **kwargs):
        if self.state == DISCONNECTED: # fixed stupid mistake
             self.log('Skip send: not connected')
             return
             
        if 'id' in kwargs:
            id = kwargs.get('id')
        else:
            id = self.msg_id
            self.msg_id += 1
            if self.msg_id > 0xFFFF:
                self.msg_id = 1
                
        if cmd == MSG_RSP:
            data = b''
            dlen = args[0]
        else:
            data = ('\0'.join(map(str, args))).encode('utf8')
            dlen = len(data)
        
        self.log('<', cmd, id, '|', *args)
        msg = struct.pack("!BHH", cmd, id, dlen) + data
        self.lastSend = gettime()
        self._write(msg)

    def connect(self):
        if self.state != DISCONNECTED: return
        self.msg_id = 1
        (self.lastRecv, self.lastSend, self.lastPing) = (gettime(), 0, 0)
        self.bin = b""
        self.state = CONNECTING
        self._send(MSG_HW_LOGIN, self.auth)

    def disconnect(self):
        if self.state == DISCONNECTED: return
        self.bin = b""
        self.state = DISCONNECTED
        self.emit('disconnected')
        self.log('Disconnected.')
        # NEW: Close the socket connection
        if self.conn:
            try:
                self.conn.close()
            except:
                pass
            self.conn = None

    def process(self, data=None):
        # NEW: Auto-reconnect logic
        if self.state == DISCONNECTED:
            self.log('Trying to reconnect...')
            self.connect()
            return # Wait for next cycle
            
        if not (self.state == CONNECTING or self.state == CONNECTED): return
        
        now = gettime()
        
        # Heartbeat check
        if now - self.lastRecv > self.heartbeat+(self.heartbeat//2):
            self.log('Heartbeat timeout.')
            return self.disconnect()
        
        # Ping check
        if (now - self.lastPing > self.heartbeat//10 and
            self.state == CONNECTED and # Only ping if fully connected
            (now - self.lastSend > self.heartbeat or
             now - self.lastRecv > self.heartbeat)):
            self._send(MSG_PING)
            self.lastPing = now
        
        if data != None and len(data):
            self.bin += data

        while True:
            if len(self.bin) < 5:
                break

            cmd, i, dlen = struct.unpack("!BHH", self.bin[:5])
            if i == 0: 
                self.log('Invalid message ID.')
                return self.disconnect()
                      
            self.lastRecv = now
            if cmd == MSG_RSP:
                self.bin = self.bin[5:]

                self.log('>', cmd, i, '|', dlen)
                if self.state == CONNECTING and i == 1:
                    if dlen == STA_SUCCESS:
                        self.state = CONNECTED
                        dt = now - self.lastSend
                        info = ['ver', __version__, 'h-beat', self.heartbeat//1000, 'buff-in', self.buffin, 'dev', sys.platform+'-py']
                        if self.tmpl_id:
                            info.extend(['tmpl', self.tmpl_id])
                            info.extend(['fw-type', self.tmpl_id])
                        if self.fw_ver:
                            info.extend(['fw', self.fw_ver])
                        self._send(MSG_INTERNAL, *info)
                        try:
                            self.emit('connected', ping=dt)
                        except TypeError:
                            self.emit('connected')
                        self.log('Connected!')
                    else:
                        if dlen == STA_INVALID_TOKEN:
                            self.emit("invalid_auth")
                            self.log("Invalid auth token")
                        return self.disconnect()
            else:
                if dlen >= self.buffin:
                    self.log("Cmd too big: ", dlen)
                    return self.disconnect()

                if len(self.bin) < 5+dlen:
                    break

                data = self.bin[5:5+dlen:]
                self.bin = self.bin[5+dlen:]

                args = list(map(lambda x: x.decode('utf8'), data.split(b'\0')))

                self.log('>', cmd, i, '|', ','.join(args))
                if cmd == MSG_PING:
                    self._send(MSG_RSP, STA_SUCCESS, id=i)
                elif cmd == MSG_HW or cmd == MSG_BRIDGE:
                    if args[0] == 'vw':
                        self.emit("V"+args[1], args[2:])
                        self.emit("V*", args[1], args[2:])
                elif cmd == MSG_INTERNAL:
                    self.emit("internal:"+args[0], args[1:])
                elif cmd == MSG_REDIRECT:
                    self.emit("redirect", args[0], int(args[1]))
                else:
                    self.log("Unexpected command: ", cmd)
                    return self.disconnect()

import socket

class Blynk(BlynkProtocol):
    def __init__(self, auth, **kwargs):
        self.insecure = kwargs.pop('insecure', False)
        self.server = kwargs.pop('server', 'blynk.cloud')
        self.port = kwargs.pop('port', 80 if self.insecure else 443)
        BlynkProtocol.__init__(self, auth, **kwargs)
        self.on('redirect', self.redirect)

    def redirect(self, server, port):
        self.server = server
        self.port = port
        self.disconnect()
        # Reconnect will happen automatically in process()

    def connect(self):
        # NEW: Prevent re-entry if already connecting
        if self.state == CONNECTING:
            return
            
        self.log('Connecting to %s:%d...' % (self.server, self.port))
        
        # NEW: Wrap entire connection in try/except
        try:
            s = socket.socket()
            s.connect(socket.getaddrinfo(self.server, self.port)[0][-1])
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                pass
            
            if self.insecure:
                self.conn = s
            else:
                try:
                    import ussl
                    ssl_context = ussl
                except ImportError:
                    import ssl
                    ssl_context = ssl
                self.conn = ssl_context.wrap_socket(s, server_hostname=self.server)
            
            try:
                self.conn.settimeout(SOCK_TIMEOUT)
            except:
                s.settimeout(SOCK_TIMEOUT)
            
            # Call base protocol connect ONLY if socket connection was successful
            BlynkProtocol.connect(self)
            
        except Exception as e:
            self.log('Error connecting:', str(e))
            self.state = DISCONNECTED # Ensure we are marked as disconnected
            # Wait before retrying so we don't spam
            print("network has lost we're going to reset the machine!")
            print("Rebooting in 5 seconds...")
            time.sleep(5)  # Add a delay to prevent a fast crash-reboot loop
            machine.reset() # Perform a hard reset 

    def _write(self, data):
        #print('<', data)
        try:
            self.conn.write(data)
        except Exception as e:
            # Handle write error (e.g., connection dropped)
            self.log('Write error:', str(e))
            self.disconnect()

    def run(self):
        data = b''
        try:
            # Check if connection exists before reading
            if self.conn:
                data = self.conn.read(self.buffin)
            #print('>', data)
        except KeyboardInterrupt:
            raise # Allow user to stop the program
        except OSError:
            # No data received, this is normal
            pass
        except Exception as e: 
            # NEW: Catch other errors (e.g. connection reset)
            self.log('Read error:', str(e))
            self.disconnect() # Force disconnect, process() will reconnect
            return # Skip processing this cycle
            
        # process() will handle pings, data, and reconnect logic
        self.process(data)
