import sys
import os
import time
import hashlib
import socket
import json
import paho.mqtt.client as mqtt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

def on_subscribe(mid, granted_qos):
    print("Subscribed: "+str(mid)+" "+str(granted_qos))
    
def on_connect(client, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("NeedDeleteFile")
    
def on_message(msg):
    command=msg.payload.decode()
    print(command)
    dict_entry = json.loads(command)
    if os.path.exists(dict_entry['file_path']) and ip_address == dict_entry['ip_address']:
        os.remove(dict_entry['file_path'])

class FilleDetector(FileSystemEventHandler):
    def on_created(self, event):
        if (event.is_directory == False):
            print("=================================")
            print(event.src_path, "New file Detected")
            print("malware checking...")
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
    client = mqtt.Client("RY-AG")
    # client.username_pw_set("cedalo", "l3n2F8XBEl")
    client.connect("103.59.95.89", 1883)
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = FilleDetector()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    print("Monitoring file dimulai....")
    observer.start()
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    try:
        while True:
            time.sleep(1)

    finally:
        observer.stop()
        observer.join()