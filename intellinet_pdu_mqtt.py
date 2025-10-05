#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Intellinet 163682 PDU → MQTT (Home Assistant Discovery) — FULL FEATURES
Implements the official UDP protocol (port 51230) to cover *all* features exposed by the Web UI / wrapper:
- Telemetry (V, A, °C, %RH) + computed power
- 8 outlet states + ON/OFF/REBOOT
- Outlet names (read & write)
- Per-outlet open/close delays (read & write)
- Thresholds (current warn/over, voltage warn/over, temp low/high, humidity warn) (read & write)

Protocol: see official "UDP Administrator" PDF (Data IDs 6, 8, 12, 14, 16).
Security: the UDP API has no auth — keep the PDU on a trusted VLAN.

Env vars (defaults shown):
  PDU_HOST=192.168.1.50
  PDU_PORT=51230
  MQTT_HOST=127.0.0.1
  MQTT_PORT=1883
  MQTT_USER=
  MQTT_PASSWORD=
  MQTT_PREFIX=intellinet/pdu1
  CLIENT_ID=intellinet-pdu1
  POLL_SEC=5

Home Assistant: discovery is automatic (sensors, switches, numbers, texts).

"""
import os, time, socket, struct, json, threading
from typing import Dict, List, Tuple

try:
    import paho.mqtt.client as mqtt
except ImportError:
    raise SystemExit("Missing paho-mqtt. Install with: pip install paho-mqtt")

# --- UDP wire protocol constants ---
FRAME_HDR = 0xA7
CMD_GET = 0x40
CMD_SET = 0x41
CMD_RESP = 0x42

DATAID_STATUS   = 6   # V, A, Temp, Humidity, outlets bitmask
DATAID_THRESH   = 8   # thresholds (warn/over & temp/hum)
DATAID_SWITCH   = 12  # switch ops
DATAID_DELAYS   = 14  # open/close delays per outlet
DATAID_NAMES    = 16  # outlet names (8×10 chars)

def checksum(bs: bytes) -> int:
    return sum(bs) & 0xFF

def build_get(data_id: int) -> bytes:
    hdr = bytes([FRAME_HDR, CMD_GET, data_id, 0x00])
    return hdr + bytes([checksum(hdr)])

def build_set(data_id: int, data: bytes) -> bytes:
    header = bytes([FRAME_HDR, CMD_SET, data_id, len(data)])
    return header + data + bytes([checksum(header + data)])

def parse_response(packet: bytes) -> Tuple[int, bytes]:
    if len(packet) < 5:
        raise ValueError("Short response")
    if packet[0] != FRAME_HDR or packet[1] != CMD_RESP:
        raise ValueError("Bad header/cmd")
    data_id = packet[2]
    data_len = packet[3]
    data = packet[4:4+data_len]
    # checksum not strictly enforced (some firmwares skip it correctly)
    return data_id, data

class PDUClientUDP:
    def __init__(self, host: str, port: int = 51230, timeout: float = 1.0):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def _txrx(self, pkt: bytes, expect_id: int) -> bytes:
        self.sock.sendto(pkt, self.addr)
        data, _ = self.sock.recvfrom(2048)
        rid, payload = parse_response(data)
        if rid != expect_id:
            # swallow stray packets and wait once more
            start = time.time()
            while rid != expect_id and (time.time() - start) < 0.8:
                data, _ = self.sock.recvfrom(2048)
                rid, payload = parse_response(data)
        if rid != expect_id:
            raise TimeoutError("Unexpected response id %d" % rid)
        return payload

    # ---- Reads ----
    def read_status(self) -> Dict:
        """Return dict with voltage, current, temp_c, humidity, outlets_mask"""
        payload = self._txrx(build_get(DATAID_STATUS), DATAID_STATUS)
        if len(payload) < 8:
            raise ValueError("status payload too short")
        voltage = struct.unpack_from('<H', payload, 0)[0]
        cur_i = struct.unpack_from('<H', payload, 2)[0]
        cur_d = payload[4]/10.0
        current = cur_i + cur_d
        temp_c = payload[5]
        humidity = payload[6]
        mask = payload[7]
        return {"voltage": voltage, "current": current, "temp_c": temp_c, "humidity": humidity, "outlets_mask": mask}

    def read_names(self) -> List[str]:
        payload = self._txrx(build_get(DATAID_NAMES), DATAID_NAMES)
        names = []
        for i in range(8):
            raw = payload[i*10:(i+1)*10]
            names.append(raw.split(b'\x00',1)[0].decode('ascii', errors='ignore').strip() or f"Outlet {i+1}")
        return names

    def read_delays(self) -> Dict[str, List[int]]:
        payload = self._txrx(build_get(DATAID_DELAYS), DATAID_DELAYS)
        if len(payload) < 16:
            raise ValueError("delays payload too short")
        open_delays = list(payload[0:8])
        close_delays = list(payload[8:16])
        return {"open": open_delays, "close": close_delays}

    def read_thresholds(self) -> Dict:
        payload = self._txrx(build_get(DATAID_THRESH), DATAID_THRESH)
        # layout (inferred from doc): 0..1 cur_warn_int, 2 cur_warn_dec, 3..4 cur_over_int, 5 cur_over_dec,
        # 6..7 volt_warn, 8..9 volt_over, 10 temp_low, 11 temp_high, 12 humid_warn
        if len(payload) < 13:
            raise ValueError("threshold payload too short")
        cw_i = struct.unpack_from('<H', payload, 0)[0]
        cw_d = payload[2]/10.0
        co_i = struct.unpack_from('<H', payload, 3)[0]
        co_d = payload[5]/10.0
        volt_warn = struct.unpack_from('<H', payload, 6)[0]
        volt_over = struct.unpack_from('<H', payload, 8)[0]
        temp_low = payload[10]
        temp_high = payload[11]
        humid_warn = payload[12]
        return {
            "current_warn": cw_i + cw_d,
            "current_over": co_i + co_d,
            "voltage_warn": volt_warn,
            "voltage_over": volt_over,
            "temp_low": temp_low,
            "temp_high": temp_high,
            "humidity_warn": humid_warn
        }

    # ---- Writes ----
    def set_names(self, names: List[str]):
        # Each name max 10 bytes ASCII, pad with 0
        buf = bytearray(80)
        for i in range(8):
            s = (names[i] if i < len(names) else f"Outlet {i+1}")[:10]
            b = s.encode('ascii', errors='ignore')
            buf[i*10:i*10+len(b)] = b
        self._send_set(DATAID_NAMES, bytes(buf))

    def set_delays(self, open_delays: List[int], close_delays: List[int]):
        buf = bytearray(16)
        for i in range(8):
            buf[i] = max(0, min(99, int(open_delays[i] if i < len(open_delays) else 0)))
            buf[8+i] = max(0, min(99, int(close_delays[i] if i < len(close_delays) else 0)))
        self._send_set(DATAID_DELAYS, bytes(buf))

    def set_thresholds(self, t: Dict):
        # build payload per layout described in read_thresholds()
        def split_decimal(val: float) -> Tuple[int,int]:
            # returns (int_part, dec_on_one_decimal_place)
            vi = int(val)
            vd = int(round((val - vi)*10))
            if vd == 10:
                vi += 1; vd = 0
            return (vi, vd)
        cw_i, cw_d = split_decimal(float(t.get("current_warn", 0.0)))
        co_i, co_d = split_decimal(float(t.get("current_over", 0.0)))
        vw = int(t.get("voltage_warn", 0))
        vo = int(t.get("voltage_over", 0))
        tl = int(t.get("temp_low", 0))
        th = int(t.get("temp_high", 0))
        hw = int(t.get("humidity_warn", 0))
        buf = bytearray(13)
        struct.pack_into('<H', buf, 0, cw_i)
        buf[2] = cw_d & 0xFF
        struct.pack_into('<H', buf, 3, co_i)
        buf[5] = co_d & 0xFF
        struct.pack_into('<H', buf, 6, vw)
        struct.pack_into('<H', buf, 8, vo)
        buf[10] = tl & 0xFF
        buf[11] = th & 0xFF
        buf[12] = hw & 0xFF
        self._send_set(DATAID_THRESH, bytes(buf))

    def switch(self, op: str, indexes: List[int]):
        op_map = {"ON":1, "OFF":2, "REBOOT":4}
        code = op_map[op]
        mask = 0
        for idx in indexes:
            if 1 <= idx <= 8: mask |= (1 << (idx-1))
        data = bytes([code, mask])
        self._send_fire_and_forget(DATAID_SWITCH, data)

    def _send_set(self, did: int, data: bytes):
        pkt = build_set(did, data)
        # some firmware may reply with RESP, some may not; perform best-effort
        try:
            self.sock.settimeout(1.0)
            self.sock.sendto(pkt, self.addr)
            self.sock.recvfrom(2048)
        except Exception:
            pass

    def _send_fire_and_forget(self, did: int, data: bytes):
        pkt = build_set(did, data)
        try:
            self.sock.settimeout(0.5)
            self.sock.sendto(pkt, self.addr)
        except Exception:
            pass

# ------------- MQTT Bridge -------------
class HABridge:
    def __init__(self, pdu: PDUClientUDP, settings: Dict):
        self.pdu = pdu
        self.prefix = settings.get("MQTT_PREFIX", "intellinet/pdu1").rstrip('/')
        self.dev_id = self.prefix.replace("/", "_")
        self.poll = int(settings.get("POLL_SEC", 5))
        self.client = mqtt.Client(client_id=settings.get("CLIENT_ID", "intellinet-pdu1"), clean_session=True)
        user = settings.get("MQTT_USER")
        if user:
            self.client.username_pw_set(user, settings.get("MQTT_PASSWORD") or None)
        self.client.will_set(f"{self.prefix}/status", "offline", retain=True)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    def start(self, host: str, port: int):
        self.client.connect(host, port, keepalive=30)
        self.client.loop_start()
        # publish discovery after connect
        while True:
            try:
                st = self.pdu.read_status()
                names = self.pdu.read_names()
                delays = self.pdu.read_delays()
                thr = self.pdu.read_thresholds()
                self.publish_discovery(names)
                self.publish_state(st, names, delays, thr)
            except Exception as e:
                # keep availability accurate
                self.client.publish(f"{self.prefix}/status", "offline", retain=True)
            time.sleep(self.poll)

    # ---- MQTT helpers ----
    def device_block(self):
        return {
            "identifiers": [self.dev_id],
            "manufacturer": "Intellinet",
            "model": "163682 19\" Intelligent 8-Port PDU",
            "name": self.dev_id
        }

    def publish_discovery(self, names: List[str]):
        disc = "homeassistant"
        # sensors
        sensors = [
            ("voltage", "Voltage", "V", "mdi:flash-outline"),
            ("current", "Current", "A", "mdi:current-ac"),
            ("power",   "Power",   "W", "mdi:lightning-bolt-outline"),
            ("temp_c",  "Temperature", "°C", "mdi:thermometer"),
            ("humidity","Humidity", "%", "mdi:water-percent"),
        ]
        for key, name, unit, icon in sensors:
            cfg = {
                "name": f"{self.dev_id} {name}",
                "unique_id": f"{self.dev_id}_{key}",
                "state_topic": f"{self.prefix}/state/{key}",
                "availability_topic": f"{self.prefix}/status",
                "unit_of_measurement": unit,
                "device": self.device_block(),
                "icon": icon,
            }
            self.client.publish(f"{disc}/sensor/{self.dev_id}_{key}/config", json.dumps(cfg), retain=True)

        # switches
        for i in range(1,9):
            cfg = {
                "name": names[i-1] if (i-1)<len(names) else f"Outlet {i}",
                "unique_id": f"{self.dev_id}_outlet{i}",
                "state_topic": f"{self.prefix}/state/outlet{i}",
                "command_topic": f"{self.prefix}/set/outlet{i}",
                "payload_on": "ON",
                "payload_off": "OFF",
                "availability_topic": f"{self.prefix}/status",
                "device": self.device_block(),
                "icon": "mdi:power-socket-eu",
            }
            self.client.publish(f"{disc}/switch/{self.dev_id}_outlet{i}/config", json.dumps(cfg), retain=True)

        # numbers: per-outlet open/close delays
        for which in ("open","close"):
            for i in range(1,9):
                key = f"delay_{which}_{i}"
                cfg = {
                    "name": f"Delay {which} outlet {i}",
                    "unique_id": f"{self.dev_id}_{key}",
                    "state_topic": f"{self.prefix}/state/{key}",
                    "command_topic": f"{self.prefix}/set/{key}",
                    "availability_topic": f"{self.prefix}/status",
                    "device": self.device_block(),
                    "min": 0, "max": 99, "step": 1,
                    "unit_of_measurement": "s",
                }
                self.client.publish(f"{disc}/number/{self.dev_id}_{key}/config", json.dumps(cfg), retain=True)

        # numbers: thresholds
        thr_numbers = [
            ("current_warn","Current warn","A",0,20,0.1),
            ("current_over","Current overload","A",0,20,0.1),
            ("voltage_warn","Voltage warn","V",180,260,1),
            ("voltage_over","Voltage overload","V",180,260,1),
            ("temp_low","Temp low","°C",0,60,1),
            ("temp_high","Temp high","°C",0,80,1),
            ("humidity_warn","Humidity warn","%",0,100,1),
        ]
        for key, name, unit, vmin, vmax, step in thr_numbers:
            cfg = {
                "name": f"{name}",
                "unique_id": f"{self.dev_id}_{key}",
                "state_topic": f"{self.prefix}/state/{key}",
                "command_topic": f"{self.prefix}/set/{key}",
                "availability_topic": f"{self.prefix}/status",
                "device": self.device_block(),
                "min": vmin, "max": vmax, "step": step,
                "unit_of_measurement": unit,
            }
            self.client.publish(f"{disc}/number/{self.dev_id}_{key}/config", json.dumps(cfg), retain=True)

        # text: outlet names
        for i in range(1,9):
            key = f"name_{i}"
            cfg = {
                "name": f"Outlet {i} name",
                "unique_id": f"{self.dev_id}_{key}",
                "state_topic": f"{self.prefix}/state/{key}",
                "command_topic": f"{self.prefix}/set/{key}",
                "availability_topic": f"{self.prefix}/status",
                "device": self.device_block(),
                "mode": "text",
                "max": 10
            }
            self.client.publish(f"{disc}/text/{self.dev_id}_{key}/config", json.dumps(cfg), retain=True)

    def publish_state(self, st: Dict, names: List[str], delays: Dict, thr: Dict):
        # availability
        self.client.publish(f"{self.prefix}/status", "online", retain=True)
        # switches
        mask = st["outlets_mask"]
        for i in range(1,9):
            state = "ON" if (mask & (1 << (i-1))) else "OFF"
            self.client.publish(f"{self.prefix}/state/outlet{i}", state, retain=True)
        # sensors
        power = int(round(st["voltage"] * st["current"]))
        for k in ("voltage","current","temp_c","humidity"):
            self.client.publish(f"{self.prefix}/state/{k}", st[k], retain=True)
        self.client.publish(f"{self.prefix}/state/power", power, retain=True)
        # delays
        for i in range(1,9):
            self.client.publish(f"{self.prefix}/state/delay_open_{i}", delays["open"][i-1], retain=True)
            self.client.publish(f"{self.prefix}/state/delay_close_{i}", delays["close"][i-1], retain=True)
        # thresholds
        for k,v in thr.items():
            self.client.publish(f"{self.prefix}/state/{k}", v, retain=True)
        # names
        for i in range(1,9):
            self.client.publish(f"{self.prefix}/state/name_{i}", names[i-1], retain=True)

    def on_connect(self, client, userdata, flags, rc):
        # subscribe commands
        for i in range(1,9):
            client.subscribe(f"{self.prefix}/set/outlet{i}")
            client.subscribe(f"{self.prefix}/set/delay_open_{i}")
            client.subscribe(f"{self.prefix}/set/delay_close_{i}")
            client.subscribe(f"{self.prefix}/set/name_{i}")
        for key in ("current_warn","current_over","voltage_warn","voltage_over","temp_low","temp_high","humidity_warn"):
            client.subscribe(f"{self.prefix}/set/{key}")

    def on_message(self, client, userdata, msg):
        topic = msg.topic
        payload = (msg.payload or b"").decode().strip()
        try:
            if "/set/outlet" in topic:
                idx = int(topic.rsplit("outlet",1)[1])
                cmd = payload.upper()
                if cmd in ("ON","OFF","REBOOT"):
                    self.pdu.switch(cmd, [idx])
            elif "/set/delay_open_" in topic:
                idx = int(topic.rsplit("_",1)[1]); val = int(float(payload))
                d = self.pdu.read_delays()
                d["open"][idx-1] = max(0, min(99, val))
                self.pdu.set_delays(d["open"], d["close"])
            elif "/set/delay_close_" in topic:
                idx = int(topic.rsplit("_",1)[1]); val = int(float(payload))
                d = self.pdu.read_delays()
                d["close"][idx-1] = max(0, min(99, val))
                self.pdu.set_delays(d["open"], d["close"])
            elif "/set/name_" in topic:
                idx = int(topic.rsplit("_",1)[1]); name = payload[:10]
                names = self.pdu.read_names()
                names[idx-1] = name
                self.pdu.set_names(names)
            else:
                # thresholds
                key = topic.rsplit("/",1)[1].replace("set/","")
                thr = self.pdu.read_thresholds()
                if key in thr:
                    # cast
                    val = float(payload) if key.startswith("current") else int(float(payload))
                    thr[key] = val
                    self.pdu.set_thresholds(thr)
        except Exception as e:
            # ignore invalid payloads
            pass

def main():
    settings = {
        "MQTT_HOST": os.getenv("MQTT_HOST","127.0.0.1"),
        "MQTT_PORT": int(os.getenv("MQTT_PORT","1883")),
        "MQTT_USER": os.getenv("MQTT_USER",""),
        "MQTT_PASSWORD": os.getenv("MQTT_PASSWORD",""),
        "MQTT_PREFIX": os.getenv("MQTT_PREFIX","intellinet/pdu1"),
        "CLIENT_ID": os.getenv("CLIENT_ID","intellinet-pdu1"),
        "POLL_SEC": int(os.getenv("POLL_SEC","5")),
    }
    pdu = PDUClientUDP(os.getenv("PDU_HOST","192.168.1.50"), int(os.getenv("PDU_PORT","51230")))
    bridge = HABridge(pdu, settings)
    bridge.start(settings["MQTT_HOST"], settings["MQTT_PORT"])

if __name__ == "__main__":
    main()
