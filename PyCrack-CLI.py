import hashlib
import time


def PyCracker(hashtype, output_file, input_hash, wordlist):
    """Uses dictionary attack to match with hashes in a file"""
    start_time = time.time()
    # open file and make it a list
    with open(input_hash, encoding='latin-1') as f:
        lines = f.read().splitlines()
        f.close()

    correct_hash = 0

    with open(wordlist, encoding='latin-1') as word_l:

        word = word_l.readlines()
        word_l.close()
        hash_len = len(lines)
        print(f'{hash_len} hashes found.\nScanning')

        for b in lines:
            for a in word:
                # hash words in dictionary
                wl_hash = hashtype(a.strip().encode('utf-8'))

                if wl_hash.hexdigest() == b:

                    correct_hash += 1
                    # open file and write match
                    f = open(output_file, 'a+')
                    to_file = f'{a.strip()}:{b}\n'
                    f.writelines(to_file)
                    # print match to user
                    print(a.strip(), ':', b)

        print(
            f'Scan finished in {time.time() - start_time}. {correct_hash}/{hash_len} hashes found.\nResults written to '
            f'{output_file}\n')


def start():
    """Function to gather relevant information for cracking hashes"""
    hash_file = input('File containing hashes: ')
    wordlist = input('Wordlist: ')
    output_file = input('File to write responses: ')
    hash_select = input('Please select from one of the hashes.\n1. MD5\n2. SHA-256\n3. SHA-512')
    hashtype = ''
    if hash_select == '1':
        hashtype = hashlib.md5
    if hash_select == '2':
        hashtype = hashlib.sha256
    if hash_select == '3':
        hashtype = hashlib.sha512

    PyCracker(hashtype, output_file, hash_file, wordlist)


if __name__ == '__main__':
    start()
