import sys
import os
import time
import hashlib
import socket
import pickle
import json
import paho.mqtt.client as mqtt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def on_subscribe(client, userdata, mid, granted_qos):
    print("Subscribed: "+str(mid)+" "+str(granted_qos))
    
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("ScanRequest")
    client.subscribe("ScanResult")
    
def on_message(client, userdata, msg):
    command=msg.payload.decode()
    print(command)
    if msg.topic == "ScanRequest":
        try:
            print("=== scanning to server ===")
            dict_entry = json.loads(command)
            if os.path.exists(dict_entry['file_path']) and ip_address == dict_entry['client_ip']:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_address = ('103.59.95.89', 5000)
                sock.connect(server_address)
                print("connected to server")
                with open(dict_entry['file_path'], 'rb') as f:
                    file_contents = f.read()
                print("file readed")
                serialized_contents = pickle.dumps(file_contents)
                sock.sendall(serialized_contents)
                sock.close()
        except Exception as e:
            print("Error", e)
    elif msg.topic == "ScanResult":
        try:
            print("=== answer from server ===")
            dict_entry = json.loads(command)
            if os.path.exists(dict_entry['file_path']) and ip_address == dict_entry['client_ip']:
                os.remove(dict_entry['file_path'])
        except Exception as e:
            print("Error", e)

class FilleDetector(FileSystemEventHandler):
    def on_created(self, event):
        if (event.is_directory == False):
            print(event.src_path, "New file Detected")
            full_path = os.path.abspath(event.src_path)
            md5_returned = hashlib.md5()
            with open(event.src_path, 'rb') as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    md5_returned.update(data)
            
            md5_returned = md5_returned.hexdigest()

            result = { 
                'client_hash': md5_returned,
                'client_ip': ip_address,
                'file_path': full_path,
                }
            # client = mqtt.Client("AG")
            # client.connect("103.59.95.89", 1883)
            string_payload = json.dumps(result)
            client.publish("CreatedFile", string_payload)
            print(string_payload)
    
    def on_deleted(self, event):
        if (event.is_directory == False):
            print("=================================")
            print(event.src_path, event.event_type)
            full_path = os.path.abspath(event.src_path)
            result = { 
                'client_ip': ip_address,
                'file_path': full_path,
                }
            string_payload = json.dumps(result)
            client.publish("DeletedFile", string_payload)
            print(string_payload)

if __name__ == "__main__":
    ip_address = socket.gethostbyname(socket.gethostname())
    client = mqtt.Client("AG")
    # client.username_pw_set("cedalo", "l3n2F8XBEl")
    client.connect("103.59.95.89", 1883)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = FilleDetector()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    print("Monitoring file dimulai....")
    
    try:
        client.loop_start()
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        client.loop_stop()
    
    finally:
        observer.join()
        client.disconnect()