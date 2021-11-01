import socket, ssl, pickle
import database.sshConnection
import database.sqlDataRetrieval

PORT = 8080

def get_dongle_data(data):
    """
    This function processes the pickle object retrieved, and prepares it for sending to DB

    :param data: raw data retrived from client
    :return (dongle_name, dongle_number): tuple containing required info for DB
    """
    dongle_data = pickle.loads(data)
    dongle_name = dongle_data[0]
    dongle_number = dongle_data[1]
    dongle_id = dongle_data[2]
    scanner_id = dongle_data[3]

    return (dongle_name, dongle_number, dongle_id, scanner_id)


def deal_with_client(connstream):
    """
    This function retrieves the incoming packets sent by the client 

    :param connstreamode: connection object from socket library
    """
    data = connstream.recv(1024)
    # empty data means the client is finished with us
    dongle_data = get_dongle_data(data)
    # finished with client
    return dongle_data

def get_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="certs/cert.pem", keyfile="certs/key.pem")
    return context

def get_bindsocket():
    bindsocket = socket.socket()
    bindsocket.bind(('', PORT))
    bindsocket.listen(5)
    return bindsocket


context = get_context()
bindsocket = get_bindsocket()

while True:
    try:
        newsocket, fromaddr = bindsocket.accept()
        connstream = context.wrap_socket(newsocket, server_side=True)
        try:
            dongle_data = deal_with_client(connstream)
        except:
            print("Error:\t\tError occured during transmission\n")

        finally:
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()

            #validate input from dongle, reject if any special character
            validate = False
            for i in dongle_data:
                v = all(c.isalnum() or c.isspace() for c in i) # false if contains non alphanumeric
                if not validate:
                    break

            if dongle_data and validate:
                try:
                    if dongle_data[3] == 0:
                        result = database.sqlDataRetrieval.updateDongleAuth_valid('dongleMan', dongle_data[0], dongle_data[1], dongle_data[2])
                        print("Server:\t\tDB successfully updated\n")
                    else:
                        # Open file for writing
                        file_dir = "/home/dongleMan/server/"
                        file_path = file_dir + str(dongle_data[3])
                        f = open(file_path, "w") 
                        sever_data_pickle = pickle.dumps(dongle_data)
                        try:
                            f.write(dongle_data[0])
                            f.write("\n")
                            f.write(dongle_data[1])
                            f.write("\n")
                            f.write(dongle_data[2])
                            print("Server:\t\tSaved in file")
                        except:
                            print("Error:\t\tCannot write to file")
                        finally:
                            f.close()

                except:
                    print("Error:\t\tDB not updated - connection error\n")
            else:
                print("Error:\t\tNo data to update\n")
    except:
        print("Error:\t\tCert verification error on client")


