import time
import requests

headers = \
    {
        "User-Agent":
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/79.0.3945.117 Safari/537.36'
    }


def subdomain_check(wordlist, URL, response, resp_check):
    """Checks the URL for subdomains that responds to the
    selected response. Removes the prefix from the URL,
    adds the subdomain then adds the prefix back when searching."""
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
    print(f'Currently searching {subdomain_URL} for code {resp_check}')
    # take a loop for each word in the wordlist
    for i in word_l:
        try:
            # add each word to the URL and test its status code response

            check_url = prot_scheme + i.strip() + subdomain_URL
            a = requests.get(check_url, headers=headers)
            if a.status_code in resp_check:
                print(f'{check_url} responds with {a.status_code}')
                with open(response, 'a+') as response_f:
                    write_match = f'{check_url.strip()} | {a.status_code}\n'
                    response_f.write(write_match)
        except requests.exceptions.MissingSchema:
            print('Invalid URL.')


def subdir_check(wordlist, URL, response, resp_check):
    """Checks the URL subdirectories that respond to the selected code. """
    print(f'Currently searching {URL} for status code {resp_check}')
    word_l = open(wordlist)
    # check every item in the wordlist variable against the URL
    for i in word_l:
        check_url = URL + i.strip()
        a = requests.get(check_url, headers=headers)
        if a.status_code in resp_check:
            print(f'{check_url} responds with {a.status_code}')
            with open(response, 'a+') as response_f:
                write_match = f'{check_url.strip()} | {a.status_code}\n'
                response_f.write(write_match)


def dir_check(URL, wordlist, response, resp_check, dd):
    start_time = time.time()
    # append / if not exists
    if URL[-1] == '/':
        pass
    elif URL[-1] != '/':
        URL += '/'
    # depending on what is provided, choose a range to scan
    if resp_check == '1':
        resp_check = range(100, 110)
    elif resp_check == '2':
        resp_check = range(200, 226)
    elif resp_check == '3':
        resp_check = range(300, 308)
    elif resp_check == '4':
        resp_check = range(400, 451)
    elif resp_check == '5':
        resp_check = range(500, 511)
    # chooses what function to initialize
    if dd == '1':
        subdomain_check(wordlist, URL, response, resp_check)

    if dd == '2':
        subdir_check(wordlist, URL, response, resp_check)

    print(f'Scan finished in {time.time() - start_time}\n',
          f'Results written to {response}\n')


def start():
    site_to_check = input('URL to scan: ')

    print('Checking URL...')

    try:
        requests.get(site_to_check)
    except requests.exceptions.MissingSchema:
        print('This does not appear to be a valid website! Please try again. ')
        start()

    # wordlist, response, resp_check, dd
    wl = input('Wordlist: ')
    try:
        open(wl, 'r')

    except FileNotFoundError:
        print('File could not be located! Please enter a valid filename.')
        start()
    response_to_check = input(
        'Response to check for:\n1. Informational [100]\n2. Success [200]\n3. Redirection [300]\n4. '
        'Client Error [400]\n5.Server Error [500]\n')
    output_file = input('Output file: ')
    try:
        open(output_file, 'a+')

    except FileNotFoundError:
        print('File could not be located! Please enter a valid filename.')
        start()

    domain_or_dir = input('Scan for:\n1. Subdomain\n2. Subdirectory')

    dir_check(site_to_check, wl, output_file, response_to_check, domain_or_dir)


if __name__ == '__main__':
    start()
