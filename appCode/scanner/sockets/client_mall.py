import socket, ssl, pprint
import os.path
import scanner.protocol as dongle
import pickle

IP = '172.25.76.228'
PORT = 8080
CERT_PATH = os.path.join("certs", "cert.pem")
SCANNER_ID = 1


def setup():
    """
    Performs SSL set up and initialisation

    :return conn connection object with server
    """
    context = ssl.create_default_context()
    context.load_verify_locations(CERT_PATH)
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname= IP)
    conn.connect((IP, PORT))
    #cert = conn.getpeercert()
    #pprint.pprint(cert)
    return conn

# make dongle the first thing that happens (before all connections)
try:
    dongle_data = dongle.get_dongle_data() 
    #dongle_data = ("Daisy the Flower","55555555","5")

    if dongle_data[0] and dongle_data[1] and dongle_data[2]:
        conn = setup()
        dongle_data = (dongle_data[0],dongle_data[1], dongle_data[2], SCANNER_ID)
        dongle_data_pickle = pickle.dumps(dongle_data)
        print("Client:\t\tSuccessfuly sent to sever")

        conn.sendall(dongle_data_pickle)
        conn.close()
        
except:
    print("Client:\t\tFailed to send to server, please try agian.")