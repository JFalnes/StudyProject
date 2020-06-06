import platform
import socket
import threading
from tkinter import *
from tkinter import messagebox
import time
import hashlib
import requests
import json
from queue import Queue
import ipaddress
import subprocess

# defining commonly used variables here
# All text displayed in the GUI is stored in list
ip_list = []
socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()
# Defining the font
FONT = ("Avenir", 14)

# Header used for requests in PyBuster
headers = \
    {
        "User-Agent":
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/79.0.3945.117 Safari/537.36'
    }

# function for updating text in the GUI text_field
def update_text(pymsg, text_field):
    """updates text in the Text widget"""
    for x in pymsg:
        # update text_field text and make text_field scroll to the end
        text_field.insert(END, x)
        text_field.see('end')


def pycrack_ini(hash_var, wl_var, user_hash, outfile_var, text_field):
    """Function for initializing the PyCracker function"""
    i_hash = hash_var.get()
    wl = wl_var.get()
    outfile = outfile_var.get()
    # try to open the file, making sure it exists
    try:
        hash_file = open(i_hash, encoding='latin-1')
        f = hash_file.read().splitlines()
        t2 = threading.Thread(target=PyCracker, args=(user_hash, outfile,
                                                      f, wl, text_field,))
        t2.start()

    except FileNotFoundError:
        warn_box = messagebox.showerror(title='Error!', message='Please enter a valid Hashfile')


def PyCracker(hashtype, output_file, input_hash, wordlist, text_field):
    """The Password Cracking function, uses user selected hashtypes, output files,
    input hashes and wordlist to hash words in a wordlist and match them to the hashes
    in the user selected hashfile"""
    correct_hash = 0
    start_time = time.time()
    try:
        # open the wordlist
        with open(wordlist, encoding='latin-1') as word_l:
            word = word_l.readlines()
            hash_len = len(input_hash)
            pycrack_text = f'\n{hash_len} hashes found.\n'
            update_text(pycrack_text, text_field)
            # for line in wordlist and for item in hash list, check if two lines match
            for a in word:
                for b in input_hash:
                    wl_hash = hashtype(a.strip().encode('utf-8'))
                    # if a match is found, print it to the file and display to user
                    if wl_hash.hexdigest() == b:
                        correct_hash += 1

                        f = open(output_file, 'a+')
                        to_file = f'{a.strip()}:{b}\n'

                        # print the match to the user
                        pycrack_text = to_file
                        update_text(pycrack_text, text_field)

                        # write the match to the output_file
                        f.writelines(to_file)
            pycrack_text = f'Scan finished in {time.time() - start_time}\n {correct_hash}/{hash_len} hashes found.\n ' \
                           f'Results written to {output_file}\n'

            update_text(pycrack_text, text_field)

    except FileNotFoundError:
        warn_box = messagebox.showerror(title='Error!', message='Please enter a valid filename')


def pybuster_ini(site_var, wl_var, outfile, v, variable, text_field):
    """Function for initializing the PyBuster function"""
    site = site_var.get()
    wordlist = wl_var.get()
    try:
        f = open(wordlist, 'r')
    except FileNotFoundError:
        warn_box = messagebox.showerror(title='Error!', message='Please enter a valid filename')

    file = outfile.get()
    dd_check = v.get()
    # start a separate thread
    t3 = threading.Thread(target=dir_check, args=(site, wordlist, file, variable, dd_check, text_field))
    t3.start()


def subdomain_check(wordlist, URL, response, resp_check, text_field):
    """Checks the URL for subdomains that responds to the
    selected response. Removes the prefix from the URL,
    adds the subdomain then adds the prefix back when searching."""

    match_found = 0
    word_l = open(wordlist)
    # If URL starts with http or https, remove this to add the subdomain
    prot_scheme = ''
    if URL.startswith('https://'):
        URL = URL[8:]
        prot_scheme = 'https://'

    if URL.startswith('http://'):
        URL = URL[7:]
        prot_scheme = 'http://'
    # add the . to the URL before adding the subdomain
    subdomain_URL = '.' + URL
    pybuster_text = f'\nCurrently searching {URL} for code {resp_check}.\nThis may take a while.'
    update_text(pybuster_text, text_field)

    try:
        # take a loop for each word in the wordlist
        for i in word_l:
            try:
                # add each word to the URL and test its status code response
                check_url = prot_scheme + i.strip() + subdomain_URL
                a = requests.get(check_url, headers=headers)
                if a.status_code in resp_check:
                    pybuster_text = f'{check_url} | {resp_check}'
                    update_text(pybuster_text, text_field)
                    match_found += 1
                    with open(response, 'a+') as response_f:
                        write_match = f'{check_url.strip()} | {a.status_code}\n'
                        response_f.write(write_match)
            except requests.exceptions.MissingSchema:
                mbox = messagebox.showerror('Invalid URL', 'Something went wrong!\nError: Invalid URL')
    except requests.exceptions.ConnectionError:
        mbox = messagebox.showerror('Invalid URL', f'Error: {requests.exceptions.ConnectionError}.'
                                                   f'\nThis may not be a subdomain!')


def subdir_check(wordlist, URL, outfile, resp_check, text_field):
    """Checks the URL subdirectories that respond to the selected code. """
    pybuster_text = f'Currently searching {URL} for status code {resp_check}\n'
    update_text(pybuster_text, text_field)
    word_l = open(wordlist)
    # check every item in the wordlist variable against the URL
    try:
        for i in word_l:
            check_url = URL + i.strip()
            a = requests.get(check_url, headers=headers)
            if a.status_code in resp_check:
                pybuster_text = f'{check_url} | {a.status_code}\n'
                update_text(pybuster_text, text_field)
                with open(outfile, 'a+') as response_f:
                    write_match = f'{check_url.strip()} | {a.status_code}\n'
                    response_f.write(write_match)
    except requests.exceptions.ConnectionError:
        pass


def dir_check(URL, wordlist, response, resp_check, dd, text_field):
    """Depending on the value provided by the user, this function initialized
    either subdomain_check or subdir_check with the selected values"""
    start_time = time.time()
    # append / if not exists
    if URL[-1] == '/':
        pass
    elif URL[-1] != '/':
        URL += '/'
    # depending on what is provided, choose a range to scan

    if resp_check.get() == 'Informational [100]':
        resp_check = range(100, 110)
    elif resp_check.get() == 'Success [200]':
        resp_check = range(200, 226)
    elif resp_check.get() == 'Redirection [300]':
        resp_check = range(300, 308)
    elif resp_check.get() == 'Client Error [400]':
        resp_check = range(400, 451)
    elif resp_check.get() == 'Server Error [500]':
        resp_check = range(500, 511)

    if dd == 1:
        subdomain_check(wordlist, URL, response, resp_check, text_field)

    if dd == 2:
        subdir_check(wordlist, URL, response, resp_check, text_field)

    # Try statement here because code crashes if not, why? We may never know
    try:
        pybuster_text = f'\nScan finished in {time.time() - start_time}\n Results written to {response}\n'
        update_text(pybuster_text, text_field)
    except:
        pass


def portscan(IP, port, outfile, text_field):
    """The portscan function, writes each match down in JSON format"""
    json_data = {IP: {
        "port": port}
    }
    # create socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # attempt a connection to the IP:PORT
        con = s.connect((IP, port))
        with print_lock:
            # when a match is found, print found port and write it to the .json file
            pymapper_text = f'{IP}:{port}, is open\n'
            update_text(pymapper_text, text_field)
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
        con.close()

    except:
        pass


def threader(ip, q, outfile, text_field):
    """The threader function, necessary to start portscanner"""
    while True:
        worker = q.get()
        portscan(ip, worker, outfile, text_field)
        q.task_done()


def thread_pool(outfile, first_port, last_port, text_field):
    """The thread pool, where threads are created to scan ports"""
    q = Queue()
    pymapper_text = f'Starting port scan {first_port},{last_port}\n'
    update_text(pymapper_text, text_field)

    startTime = time.time()

    for x in range(100):
        # start a new thread for each ip in the list
        for ip in ip_list:
            t = threading.Thread(target=threader, args=(ip, q, outfile, text_field))
            t.daemon = True
            t.start()
    # for every ip, start a worker and check the ports
    for ip in ip_list:
        # starts a new thread for each number in selected range
        for worker in range(first_port, last_port):
            q.put(worker)

    q.join()
    pymapper_text = f'Port Scan: {time.time() - startTime}\n'
    update_text(pymapper_text, text_field)


def ip_scan(ip, first_port, last_port, outfile, text_field):
    """Function for IP scanning a subnet"""

    # define variables
    net4 = ipaddress.ip_network(ip)
    startTime = time.time()
    # check what platform is running, determine param
    if platform.system() == 'Windows':
        param = '-n'
    elif platform.system() == 'Linux':
        param = '-c'
    ip_scanned = 0
    ip_found = 0
    # scan every ip in net4.hosts, this is dependent upon what the subnet mask is
    for x in net4.hosts():
        try:
            rep = subprocess.check_output(f'ping {param} 1 ' + str(x), shell=True)
            # each loop ip_scanned is + 1
            ip_scanned += 1
            # if ip_scanned is a multiple of 5, print out, ensuring the user the program is still running
            if 'unreachable' in str(rep):
                pass
            else:
                ip_list.append(str(x))
                pymapper_text = f'Match ({x})\n'
                update_text(pymapper_text, text_field)
                ip_found += 1
            if ip_scanned % 5 == 0:
                pymapper_text = f'{ip_scanned} addresses scanned, {ip_found} addresses found\n'
                update_text(pymapper_text, text_field)

        except subprocess.CalledProcessError:
            pass
    thread_pool(outfile, first_port, last_port, text_field)
    pymapper_text = f'Network Scan Finished in: {time.time() - startTime}\n\n' \
                    f'Results written to {outfile}\n'
    update_text(pymapper_text, text_field)


def pymap_ini(ip_var, subnet_var, outfile, f_port, l_port, text_field):
    """Pymap initializer function"""
    # extract information from StringVar using get() method
    IP_A = ip_var.get()
    CIDR = subnet_var.get()
    F_IP = IP_A + '/' + str(CIDR)
    first_port = f_port.get()
    last_port = l_port.get()
    output_file = outfile.get()

    # check if port number and subnet mask are within the acceptable range
    if (65535 >= int(first_port) >= 1) and (65535 >= int(last_port) >= 1):
        if 30 >= CIDR >= 0:
            pymapper_text = 'Scanning\nThis may take a while.\n'
            update_text(pymapper_text, text_field)
            # start a thread running the ip_scan
            t4 = threading.Thread(target=ip_scan, args=(F_IP, first_port, last_port, output_file, text_field,))
            t4.start()
        elif CIDR > 30 or CIDR < 0:
            mbox = messagebox.showwarning('Error!', 'Please enter a valid Subnet Mask. Between 0 and 30.')
    else:
        mbox = messagebox.showwarning('Error!', 'Please enter a valid Port Number. Between 1 and 65535.')


def success_login(site, username, password, outfile, text_field):
    """Initialized when a successful login is completed"""
    pylogin_text = f'Successful login on {site}!\nSuccessful combination: {username}:{password}\n'
    update_text(pylogin_text, text_field)
    # write match to file
    f = open(outfile, 'a+')
    to_file = f'{username.strip()}:{password}\n'
    f.writelines(to_file)


def PyLogin(url, username, wordlist, success_site, outfile, text_field):
    """The PyLogin function, sends a POST request to a webserver and returns the response URL"""
    startTime = time.time()

    pylogin_text = 'Scanning\n'
    update_text(pylogin_text, text_field)
    tries = 0
    open_wl = open(wordlist, 'r', encoding='latin-1')
    # start a requests session
    with requests.Session() as s:
        # for each line in wl, attempt a login
        for line in open_wl:
            tries += 1
            password = line.strip()
            headers1 = {'Cookie': 'wordpress_test_cookie=WP Cookie check'}
            datas = {
                'log': username, 'pwd': password, 'wp-submit': 'Log In',
                'redirect_to': success_site, 'testcookie': '1'
            }
            # post to website
            s.post(url, headers=headers1, data=datas)
            # get response
            resp = s.get(success_site)
            # if resp.url is success site, initialize success_login function and break
            if resp.url == success_site:
                success_login(url, username, password, outfile, text_field)
                break
            else:
                # if not print out amount of tries
                if (tries % 100) == 0:
                    pylogin_text = f'{tries} tries attempted!\n'
                    update_text(pylogin_text, text_field)
        pylogin_text = f'Scan finished in {time.time() - startTime}\n\n'
        update_text(pylogin_text, text_field)


def pylogin_ini(site, username, wordlist, outfile, text_field):
    """Initializer function for PyLogin tool"""
    # extract information from StringVar using get() method
    site = site.get()
    # make sure site exists
    try:
        requests.get(site)
    except requests.exceptions.MissingSchema:
        site = 'http://' + site
        requests.get(site)

    username = username.get()
    wordlist = wordlist.get()
    outfile = outfile.get()
    wp_admin = site + '/wp-admin/'
    URL = site + '/wp-login.php'
    t6 = threading.Thread(target=PyLogin, args=(URL, username, wordlist, wp_admin, outfile, text_field,))
    t6.start()


class PyHack(Tk):
    """The tkinter class, sets the base for what later becomes StartPage, PyCrackFrame, etc """
    def __init__(self, *args, **kwargs):
        Tk.__init__(self, *args, **kwargs)
        container = Frame(self)
        # pack containers and configure grid
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        # set the title, geometry and disable resizing
        self.title('PyHack - Study Project 2')
        self.geometry('500x600')
        self.resizable(False, False)
        # create frames
        self.frames = {}
        for F in (StartPage, PyCrackFrame, PyBusterFrame, PyMapFrame, PyLoginFrame):
            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


class StartPage(Frame):
    """The StartPage script, the page which the user is greeted when first starting the program"""

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        label = Label(self, text="PyHack", font=FONT)
        label.pack(pady=10, padx=10)
        # create buttons and pack them, buttons lead to other frames for the tools
        button = Button(self, text="PyCrack",
                        command=lambda: controller.show_frame(PyCrackFrame))
        button.pack()

        button2 = Button(self, text="PyBuster",
                         command=lambda: controller.show_frame(PyBusterFrame))
        button2.pack()

        button3 = Button(self, text="PyMap",
                         command=lambda: controller.show_frame(PyMapFrame))
        button3.pack()

        button4 = Button(self, text="PyLogin",
                         command=lambda: controller.show_frame(PyLoginFrame))
        button4.pack()


class PyCrackFrame(Frame):
    """Class for displaying PyCracks GUI Frame"""
    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        # create entries in the hashmenu, later used to decide which hashes are being cracked
        hashmenu = ['MD5', 'SHA-256', 'SHA-512']
        # create the title label and set font
        title_lbl = Label(self, text="PyCrack", font=FONT)
        title_lbl.pack(pady=10, padx=10)

        desc_lbl = Label(self, text='A Simple Password Cracker')
        desc_lbl.pack(pady=10, padx=10)
        # define stringvars, later extracted in pycrack_ini function
        hash_var = StringVar()
        wl_var = StringVar()
        outfile = StringVar()
        # creates labels and entry boxes for users
        label_hash = Label(self, text='Hash:')
        entry_hash = Entry(self, textvar=hash_var)
        label_hash.pack()
        entry_hash.pack()

        lbl_wl = Label(self, text='Wordlist:')
        entry_wl = Entry(self, textvar=wl_var)
        lbl_wl.pack()
        entry_wl.pack()

        # create dropdown menu
        hash_select = StringVar(self)
        hash_select.set(hashmenu[0])

        label_hashtype = Label(self, text='Hashtype:')
        entry_hashtype = OptionMenu(self, hash_select, *hashmenu)
        label_hashtype.pack()
        entry_hashtype.pack()

        # when initialized, change value
        def change_dropdown_item(*args):
            """Changes value of the dropdown menu and returns the correct method """
            global user_hash

            if hash_select.get() == 'MD5':
                user_hash = hashlib.md5
            if hash_select.get() == 'SHA-256':
                user_hash = hashlib.sha256
            if hash_select.get() == 'SHA-512':
                user_hash = hashlib.sha512
            return user_hash

        # initializes change_dropdown when menu is changed
        hash_select.trace('w', change_dropdown_item)

        lbl_outfile = Label(self, text='Output File:')
        lbl_outfile.pack()

        entry_outfile = Entry(self, textvar=outfile)
        entry_outfile.pack()
        # defines buttons, buttons do commands to initialize different functions
        a_btn = Button(self, text='Run', relief='raised',
                       command=lambda: pycrack_ini(hash_var, wl_var, user_hash, outfile, text_field))
        a_btn.pack()

        button1 = Button(self, text="Back to Home",
                         command=lambda: controller.show_frame(StartPage))
        button1.pack()

        # creates a Canvas widget, creates a Scrollbar and a textfield on the Canvas
        canvas1 = Canvas(self)
        scroll_bar = Scrollbar(canvas1, orient=VERTICAL, command=canvas1.yview)
        scroll_bar.pack(side=RIGHT, fill=Y)
        # pycrack_text variable defines what is written to teh text_field at all times
        pycrack_text = 'Welcome to PyCrack!\n'
        text_field = Text(canvas1, bg='black', fg='white', yscrollcommand=scroll_bar.set)
        text_field.pack(side=BOTTOM)

        # configure scrollbar to work on text_field
        scroll_bar.config(command=text_field.yview)
        canvas1.config(yscrollcommand=scroll_bar.set)

        # update text in text_field with pymapper_text
        update_text(pycrack_text, text_field)

        canvas1.pack()


class PyBusterFrame(Frame):
    """Class for displaying PyBuster GUI Frame"""

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)

        title_lbl = Label(self, text="PyBuster", font=FONT)
        title_lbl.pack(pady=10, padx=10)

        desc_lbl = Label(self, text='A Simple Directory Finder')
        desc_lbl.pack(pady=10, padx=10)
        # create entries in the menu, later used to decide which status codes are being checked for
        respmenu = ['Informational [100]', 'Success [200]', 'Redirection [300]', 'Client Error [400]',
                    'Server Error [500]']
        # define stringvars and intvar
        site_var = StringVar()
        wl_var = StringVar()
        outfile = StringVar()
        v = IntVar()
        # creates labels and entry boces for users
        label_hash = Label(self, text='Site/URL:')
        entry_hash = Entry(self, textvar=site_var)
        label_hash.pack()
        entry_hash.pack()
        variable = StringVar(self)
        variable.set(respmenu[0])

        # when dropdown value is changed
        def change_dropdown(*args):
            print(variable.get())

        variable.trace('w', change_dropdown)

        lbl_wl = Label(self, text='Wordlist:')
        entry_wl = Entry(self, textvar=wl_var)
        lbl_wl.pack()

        entry_wl.pack()
        lbl_outfile = Label(self, text='Output:')
        lbl_outfile.pack()

        entry_outfile = Entry(self, textvar=outfile)

        entry_outfile.pack()
        entry_resp = OptionMenu(self, variable, *respmenu)
        entry_resp.pack()

        v.set(1)
        sub_domain = Radiobutton(self, text='Subdomain', variable=v, value=1)
        sub_directory = Radiobutton(self, text='Sub Directory', variable=v, value=2)
        sub_domain.pack()
        sub_directory.pack()

        a_btn = Button(self, text='Run', relief='raised',
                       command=lambda: pybuster_ini(site_var, wl_var, outfile, v, variable, text_field))
        a_btn.pack()
        button1 = Button(self, text="Back to Home",
                         command=lambda: controller.show_frame(StartPage))
        button1.pack()
        canvas1 = Canvas(self)
        # create scrollbar widget
        scroll_bar = Scrollbar(canvas1, orient=VERTICAL, command=canvas1.yview)
        scroll_bar.pack(side=RIGHT, fill=Y)

        pymapper_text = 'Welcome to PyBuster!\n'
        text_field = Text(canvas1, bg='black', fg='white', yscrollcommand=scroll_bar.set)
        text_field.pack(side=BOTTOM)

        scroll_bar.config(command=text_field.yview)
        canvas1.config(yscrollcommand=scroll_bar.set)
        update_text(pymapper_text, text_field)
        canvas1.pack()


class PyMapFrame(Frame):
    """Class for displaying PyMaps GUI Frame"""

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        title_lbl = Label(self, text="PyMapper", font=FONT)
        title_lbl.pack(pady=10, padx=10)

        desc_lbl = Label(self, text='A Simple Network Mapper')
        desc_lbl.pack(pady=10, padx=10)

        ip_var = StringVar()
        subnet_var = IntVar()
        outfile = StringVar()
        f_port = IntVar()
        l_port = IntVar()

        label_hash = Label(self, text='IP:')
        entry_hash = Entry(self, textvar=ip_var)
        label_hash.pack()
        entry_hash.pack()

        lbl_subnet = Label(self, text='Subnet mask')
        entry_subnet = Entry(self, textvar=subnet_var)
        lbl_subnet.pack()
        entry_subnet.pack()

        lbl_outfile = Label(self, text='Output:')
        entry_outfile = Entry(self, textvar=outfile)
        lbl_outfile.pack()
        entry_outfile.pack()

        lbl_startport = Label(self, text='First Port')
        lbl_startport.pack()

        start_port = Entry(self, textvar=f_port)
        start_port.pack()

        lbl_endport = Label(self, text='Last port')
        lbl_endport.pack()

        end_port = Entry(self, textvar=l_port)
        end_port.pack()

        a_btn = Button(self, text='Run', relief='raised',
                       command=lambda: pymap_ini(ip_var, subnet_var, outfile, f_port, l_port, text_field))
        a_btn.pack()
        button1 = Button(self, text="Back to Home",
                         command=lambda: controller.show_frame(StartPage))
        button1.pack()
        canvas1 = Frame(self)

        scroll_bar = Scrollbar(canvas1, orient=VERTICAL)
        scroll_bar.pack(side=RIGHT, fill=Y)

        pymapper_text = 'Welcome to PyMapper!\n'
        text_field = Text(canvas1, bg='black', fg='white', yscrollcommand=scroll_bar.set)
        text_field.pack(side=BOTTOM)
        scroll_bar['command'] = text_field.yview
        update_text(pymapper_text, text_field)

        canvas1.pack()


class PyLoginFrame(Frame):
    """Class for displaying PyLogins GUI Frame"""

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        title_lbl = Label(self, text="PyLogin", font=FONT)
        title_lbl.pack(pady=10, padx=10)

        desc_lbl = Label(self, text='A Simple Login Cracker')
        desc_lbl.pack(pady=10, padx=10)

        # defining stringvars for textvar
        URL_Var = StringVar()
        username = StringVar()
        pass_wl = StringVar()
        outfile = StringVar()

        label_URL = Label(self, text='URL:')
        entry_URL = Entry(self, textvar=URL_Var)
        label_URL.pack()
        entry_URL.pack()

        lbl_username = Label(self, text='Username:')
        entry_username = Entry(self, textvar=username)
        lbl_username.pack()
        entry_username.pack()

        lbl_passfile = Label(self, text='Password Wordlist:')
        entry_passfile = Entry(self, textvar=pass_wl)
        lbl_passfile.pack()
        entry_passfile.pack()

        lbl_outfile = Label(self, text='Output File: ')
        entry_outfile = Entry(self, textvar=outfile)
        lbl_outfile.pack()
        entry_outfile.pack()

        a_btn = Button(self, text='Run', relief='raised',
                       command=lambda: pylogin_ini(URL_Var, username, pass_wl, outfile, text_field))
        a_btn.pack()

        button1 = Button(self, text="Back to Home",
                         command=lambda: controller.show_frame(StartPage))
        button1.pack()
        canvas1 = Canvas(self)

        scroll_bar = Scrollbar(canvas1, orient=VERTICAL, command=canvas1.yview)
        scroll_bar.pack(side=RIGHT, fill=Y)

        pylogin_text = 'Welcome to PyLogin!\n'
        text_field = Text(canvas1, bg='black', fg='white', yscrollcommand=scroll_bar.set)
        text_field.pack(side=BOTTOM)

        scroll_bar.config(command=text_field.yview)
        canvas1.config(yscrollcommand=scroll_bar.set)
        canvas1.pack()

        update_text(pylogin_text, text_field)


# function for starting the GUI
def start_app():
    """Function for starting GUI in mainloop"""
    app = PyHack()
    app.mainloop()


# thread which starts the GUI
t1 = threading.Thread(target=start_app)
t1.start()
