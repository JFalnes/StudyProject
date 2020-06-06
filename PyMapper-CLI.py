import socket
import time
import threading
import subprocess
import json
from queue import Queue
import ipaddress
import platform

socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()
ip_list = []


def portscan(IP, port, outfile):
    """The portscan function, writes each match down in JSON format"""
    json_data = {IP: {
        "port": port}
    }
    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # attempt a connection to the IP:PORT
        con = s.connect((IP, port))
        with print_lock:
            # when a match is found, print found port and write it to the .json file
            print(IP, port, 'is open')
            # uses json library to write to file
            with open(outfile, 'ab+') as json_f:
                json_f.seek(0, 2)
                if json_f.tell() == 0:
                    json_f.write(json.dumps([json_data], indent=2).encode())
                else:
                    json_f.seek(-1, 2)

                    # Remove the last character, open the array
                    json_f.truncate()

                    # separate json objects
                    json_f.write(' , '.encode())

                    # dump dictionary to json_data
                    json_f.write(json.dumps(json_data, indent=2).encode())
                    json_f.write(']'.encode())
        # close connection
        con.close()

    except:
        pass


def threader(ip, q, outfile):
    """The threader function, necessary to start portscanner"""
    while True:
        worker = q.get()
        portscan(ip, worker, outfile)
        q.task_done()


def thread_pool(outfile, first_port, last_port):
    """The thread pool, where threads are created to scan ports"""
    q = Queue()
    print('Starting port scan')
    startTime = time.time()

    for x in range(100):
        # start a new thread for each ip in the list
        for ip in ip_list:
            t = threading.Thread(target=threader, args=(ip, q, outfile))
            t.daemon = True
            t.start()
    # for every ip, start a worker and check the ports
    for ip in ip_list:
        # starts a new thread for each number in selected range
        for worker in range(first_port, last_port):
            q.put(worker)

    q.join()
    print('Port Scan:', time.time() - startTime)


def ip_scan(ip, first_port, last_port, outfile):
    """Function for IP scanning a subnet"""
    startTime = time.time()
    # define variables
    ip_scanned = 0
    ip_found = 0
    net4 = ipaddress.ip_network(ip)

    # check if the system is windows or linux, determine the parameter depending on system
    if platform.system() == 'Windows':
        param = '-n'
    elif platform.system() == 'Linux':
        param = '-c'
    # for each IP in hosts, ping that host
    for x in net4.hosts():
        try:
            # ping ip
            rep = subprocess.check_output(f'ping {param} 1 ' + str(x), shell=True)
            # each loop ip_scanned is + 1
            ip_scanned += 1
            if 'unreachable' in str(rep):
                pass
            else:
                ip_list.append(str(x))
                print(f'Match ({x})')
                ip_found += 1
            # if ip_scanned is a multiple of 5, print out, ensuring the user the program is still running
            if ip_scanned % 5 == 0:
                print(f'{ip_scanned} addresses scanned, {ip_found} addresses found')

        except subprocess.CalledProcessError:
            pass
    thread_pool(outfile, first_port, last_port)
    print(f'Network Scan Finished in: {time.time() - startTime}\nResults written to {outfile}\n')


def PyMapper():
    """A function for gathering information to ip and port scan"""
    IP_A = input('IP: ')
    if IP_A.endswith('0'):

        CIDR = input('Subnet: ')

        # determines if the CIDR identifier is within the acceptable range.
        if 30 >= int(CIDR) >= 0:
            pass
        else:
            print('Please enter a valid Subnet Mask. Between 16 and 30.')
            PyMapper()

        F_IP = IP_A + '/' + CIDR
        first_port = input('First Port: ')
        last_port = input('Last Port: ')

        # ensure that the port number is a digit
        if first_port.isdigit() and last_port.isdigit():
            # check that the port is within the acceptable range
            if (65535 >= int(first_port) >= 1) and (65535 >= int(last_port) >= 1):
                first_port = int(first_port)
                last_port = int(last_port)
                outfile = input('Enter output file: ')
                try:
                    # ensure the file actually exists
                    open(outfile)
                    if outfile.endswith('.json'):
                        ip_scan(F_IP, first_port, last_port, outfile)
                    else:
                        print('Invalid file format! Please enter a .json file.')
                except FileNotFoundError:
                    print(f'File {outfile} not found, please enter a valid file.  Must be .json')
                    PyMapper()
            else:
                print('Please enter a valid port number. Must be between 1 and 65535')
                PyMapper()
    else:
        print('This does not seem to be a proper IP. Remember to remove host bits. '
              'Example: 192.168.0.0 is valid, 192.168.0.1 is not.')
        PyMapper()


# run the script
if __name__ == '__main__':
    PyMapper()
