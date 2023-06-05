import sys
import os
import time
import hashlib
import json
import paho.mqtt.client as mqtt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import socket
import requests

url = "http://103.59.95.89:5000/upload"

def on_subscribe(client, userdata, mid, granted_qos):
    print("Subscribed: "+str(mid)+" "+str(granted_qos))

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("ScanRequest", qos=1)
    client.subscribe("ScanResult", qos=2)
    
def on_message(client, userdata, msg):
    command=msg.payload.decode()
    if msg.topic == "ScanRequest":
        try:
            dict_entry = json.loads(command)
            if os.path.exists(dict_entry['file_path']) and ip_address == dict_entry['client_ip']:
                try:
                    print(dict_entry)
                    print("=== scan to server ===")
                    files = {"file": open(dict_entry['file_path'], 'rb')}
                    data = {
                        "client_ip": dict_entry['client_ip'],
                        "file_path": dict_entry['file_path']
                    }
                    
                    # Send the request
                    response = requests.post(url, files=files, data=data)
                    
                    if response.status_code == 200:
                        print('File uploaded successfully.')
                    else:
                        print('Upload failed with status code:', response.status_code)
                        print('Error message:', response.text)
                except Exception as e:
                    print("Error", e)
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
        if (not event.is_directory and not event.src_path.endswith(".part")):
            print(event.src_path, "New file Detected")
            full_path = os.path.abspath(event.src_path)
            time.sleep(1)
            md5_returned = calculate_hash(full_path)

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
            full_path = os.path.abspath(event.src_path)
            
            if not os.path.exists(full_path):
                print("=================================")
                print(event.src_path, event.event_type)
                
                result = { 
                    'client_ip': ip_address,
                    'file_path': full_path,
                    }
                string_payload = json.dumps(result)
                client.publish("DeletedFile", string_payload)
                print(string_payload)
            
def calculate_hash(file_path):
    hash_algorithm = hashlib.md5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(65536), b""):
            hash_algorithm.update(chunk)

    md5_returned = hash_algorithm.hexdigest()
    return md5_returned

if __name__ == "__main__":
    ip_address = socket.gethostbyname(socket.gethostname())
    print(f"IP ADDRESS: {ip_address}")
    client = mqtt.Client("Agent")
    # client.username_pw_set("cedalo", "l3n2F8XBEl")
    client.connect("103.59.95.89", 1883)
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.loop_start()
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = FilleDetector()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    print("Monitoring file dimulai....")
    online_payload = { 
                'client_ip': ip_address,
                }
    string_online_payload = json.dumps(online_payload)
    client.publish("online", string_online_payload)

    try:
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        client.loop_stop()
    finally:
        observer.join()
        client.disconnect()