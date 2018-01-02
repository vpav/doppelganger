#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  doppelganger.py
#  
#  Copyright 2017 Viktor Pavlovic <vi@phy.re>
#  
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#  
#  

#
# Doppelgänger is a tool that creates permutations of domain names using lookalike
# unicode characters and identifies registered domains using dns queries.
# It can be used to identify phishing domains.
#
#

#
# TODO:
#
# convert input domain to lowercase
# dns round robin for speed increase / not get blocked
# use better algorithm for permutation generation (ram + speed)
# use hdf5 for working with datasets larger than ram

#from __future__ import print_function
import itertools
import dns.resolver
from colorama import init, Fore, Back, Style
import csv
import getopt, sys
import argparse
import textwrap
import time
import datetime
import os

show_char_alts = False  # show lookalike chars for each character
show_permutations = False  # show all permutations for domain
show_debug = False
show_colors = True  # enable color console output
show_time = False  # enable benchmark for permutation finding

iinfo = "[i] "
isucc = "[+] "
iwarn = "[!] "
ierr = "[-] "

supported_tlds = ['com', 'org', 'at', 'ca', 'ch', 'de', 'dk', 'fr', 'no', 'pm', 'se', 'tf', 'wf', 'yt']


class mainOptions():
    def __init__(self):
        # number of permutations that can be done in reasonable time using the original (complete) algorithm
        self.max_permutations = 20000

        # Use Colors
        self.show_colors = True

        # Show Debug Output
        self.show_debug = False

        # show all permutations for domain
        self.show_permutations = False

        self.data = []


opt = mainOptions()


def init_helpers():
    global iinfo, iwarn, isucc, ierr

    if show_colors:
        init()
        iinfo = Fore.LIGHTBLUE_EX + "[i] " + Style.RESET_ALL
        isucc = Fore.LIGHTGREEN_EX + "[+] " + Style.RESET_ALL
        iwarn = Fore.YELLOW + "[!] " + Style.RESET_ALL
        ierr = Fore.RED + "[-] " + Style.RESET_ALL
    else:
        iinfo = "[i] "
        isucc = "[+] "
        iwarn = "[!] "
        ierr = "[-] "


class PermutationError(Exception):
    pass


def show_tld_support():
    ccomplete = "complete"
    cnotsupported = "IDN not supported"
    cpartial = "partial"
    cpartialend = ""
    if show_colors:
        ccomplete = Fore.LIGHTGREEN_EX + "complete" + Style.RESET_ALL
        cnotsupported = Fore.BLUE + "IDN not supported" + Style.RESET_ALL
        cpartial = Fore.YELLOW + "partial"
        cpartialend = Style.RESET_ALL

    print("                             TLD Support")
    print("####################################################################")
    print("")
    print("gTLDs")
    print("-------+------------------------------------------------------------")
    print("com    | " + cpartial + " - only latin and lisu script" + cpartialend)
    print("org    | " + cpartial + " - Korean and Chinese missing" + cpartialend)
    print("net    | " + cpartial + " - only latin and lisu script" + cpartialend)
    print("sTLDs")
    print("biz    | no")
    print("info   | no")
    print("name   | no")
    print("")
    print("ccTLDs")
    print("-------+------------------------------------------------------------")
    print("ag     | no")
    print("ar     | no")
    print("at     | " + ccomplete)
    print("au     | " + cnotsupported)

    print("be     | no")
    print("br     | no")

    print("ca     | not applicable (https://cira.ca/assets/Documents/Legal/IDN/faq.pdf)")
    print("ch     | " + ccomplete)
    print("cn     | no")
    print("co     | no")
    print("cz     | no")

    print("de     | " + ccomplete)
    print("dk     | " + ccomplete)


    print("es     | no")
    print("eu     | no")  #

    print("fi     | no")
    print("fm     | no")  #
    print("fr     | " + ccomplete)

    print("gr     | no")

    print("hu     | no")
    print("hr     | no")

    print("ie     | no")
    print("in     | no")
    print("io     | no")  #
    print("ir     | " + cnotsupported)
    print("is     | no")
    print("it     | no")  # charsets, no homoglyphs, http://www.crdd.it/norme/GuidelineTecnicheSincrono2.1-EN.pdf

    print("jp     | no")

    print("me     | no")

    print("nl     | " + cnotsupported)
    print("no     | " + ccomplete)

    print("pl     | no") # 4 language sets: latin, greek, cyrillic, - lookalike check in place hebrew https://www.dns.pl/IDN/idn-registration-policy.txt
    print("pm     | " + ccomplete)

    print("рф (rf)| no")
    print("rs     | no")
    print("ru     | " + cnotsupported)

    print("se     | " + cpartial + " - no hebrew support" + cpartialend)

    print("tf     | " + ccomplete)
    print("tr     | no")
    print("tv     | no")
    print("tw     | no")

    print("uk     | " + cnotsupported)
    print("us     | " + cnotsupported)

    print("wf     | " + ccomplete)

    print("yt     | " + ccomplete)


def main(args):
    global parsed_args
    global show_colors
    parser = argparse.ArgumentParser(prog='doppelganger',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''doppelganger - A tool to search for IDN lookalike/fake domains
                                                 \nCopyright \u00a9 2017 Viktor Pavlovic
\n This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see http://www.gnu.org/licenses/ .'''),
        epilog='''General Note: Some characters seem to be easily distinguishable from others.
              However on some fonts, sizes, uppercase letters, etc. these
              could look alike, so they are included just to be sure.

Another Note: Keep in mind that while some doppelganger domains are created
              with malicious intent, some are not. Some domains identified by
              this tool were probably not meant to be a doppelganger of the
              original.''')
    parser.add_argument("-1", "--simple", help="Force simple algorithm: Modify only one character at a time. "
                                               "Overrides --max-permutations (-p) setting.",
                        action="store_true")
    parser.add_argument("-c", "--colors", help="Switch output colors on (1) and off (0). Defaults to on.",
                        type=int, choices=[0, 1], default=0)
    parser.add_argument("-d", "--dry-run", help="Create and output permutations, don't do any DNS requests.",
                        action="store_true")
    parser.add_argument("-k", "--keymap", help="Use specified keymap for finding typo domains.",
                        type=str, choices=['qwerty', 'qwertz', 'azerty'], default='qwerty')
    parser.add_argument("-o", "--output-file", help="Output permutations to file, don't do anything else.",
                        type=str, metavar="Filename")
    parser.add_argument("-p", "--max-permutations", help="number of calculated permutations after a switch to a simpler"
                                                         " algorithm is done. By default this software looks for all "
                                                         "doppelganger characters, however on domains with less "
                                                         "restrictive IDN rules this can easily result in several "
                                                         "million permutations that would take really long to check. "
                                                         "Simpler algorithm: Modify only one character at a time. "
                                                         "Defaults to 20000",
                        type=int, default=20000)
    parser.add_argument("-s", "--tld-support", help="Show a table of supported TLDs.",
                        action="store_true")
    parser.add_argument("-t", "--timing", help="Set a ms delay between DNS queries to prevent flooding DNS servers",
                        type=int, default=0)
    parser.add_argument("-v", "--verbose", action="count", help="verbose output", default=0)
    parser.add_argument("-y", "--typo-only", action="store_true", help="Generate typos, not doppelgangers", default=0)
    parser.add_argument("domain", help="the fqdn you want to check", nargs='?')
    parsed_args = parser.parse_args()
    if parsed_args.colors:
        if parsed_args.colors == 1:
            show_colors = True
        else:
            show_colors = False
    init_helpers()
    if parsed_args.tld_support:
        show_tld_support()
        sys.exit()
    if not parsed_args.domain:
        print(ierr + "FQDN missing")
        parser.print_help()
        sys.exit()

    if parsed_args.verbose:
        show_debug = True

    if parsed_args.typo_only:
        checkTypo(parsed_args.domain)
    else:
        checkDoppel(parsed_args.domain)
        # checkDoppel("ubedoga.org")
    return 0


def replace_lisu(sll):
    out = ""

    for c in sll:
        if c == 'a':
            r = 0xa4ee
        elif c == 'b':
            r = 0xa4d0
        elif c == 'c':
            r = 0xa4da
        elif c == 'd':
            r = 0xa4d3
        elif c == 'e':
            r = 0xa4f0
        elif c == 'f':
            r = 0xa4dd
        elif c == 'g':
            r = 0xa4d6
        elif c == 'h':
            r = 0xa4e7
        elif c == 'i':
            r = 0xa4f2
        elif c == 'j':
            r = 0xa4d9
        elif c == 'k':
            r = 0xa4d7
        elif c == 'l':
            r = 0xa4e1
        elif c == 'm':
            r = 0xa4df
        elif c == 'n':
            r = 0xa4e0
        elif c == 'o':
            r = 0xa4f3
        elif c == 'p':
            r = 0xa4d1
        elif c == 'r':
            r = 0xa4e3
        elif c == 's':
            r = 0xa4e2
        elif c == 't':
            r = 0xa4d4
        elif c == 'u':
            r = 0xa4f4
        elif c == 'v':
            r = 0xa4e6
        elif c == 'w':
            r = 0xa4ea
        elif c == 'x':
            r = 0xa4eb
        elif c == 'y':
            r = 0xa4ec
        elif c == 'z':
            r = 0xa4dc
        else:
            r = ord(c)

        out += chr(r)

    return out


def get_permutations(sll, tld, lang_code='none'):
    pos = 0
    sll_alts = []
    all_permutations = []

    if lang_code == 'lisu':
        if 'q' in sll:
            if show_debug:
                print('q is not available in lisu - no alternatives.')
            return all_permutations
        else:
            all_permutations.append(replace_lisu(sll) + '.' + tld + tld)
            return all_permutations

    if tld == 'se' and lang_code == 'hebrew':
        if ['a','b','c','d','e','f','g','h','j','k','m','p','r','s','v','w','z']:
            if show_debug:
                print('some letters are not available in hebrew - no alternatives.')
            return all_permutations

    for c in sll:
        if show_char_alts:
            print(c, end='')
            print(" Alternatives: ", end='')
        curr_char = [c]

        for altc in alt_chars(c, tld, lang_code):
            if show_char_alts:
                print(chr(altc) + " ", end='')
            curr_char.append(chr(altc))

        if show_char_alts:
            print("")
        pos += 1
        sll_alts.append(curr_char)

    if parsed_args.simple:
        print(iinfo + "Using simpler algorithm (will contain only domains with one modified character)")
        all_permutations = get_simple_permutations(sll, tld, lang_code)
    else:
        try:
            for permutation in getcombinations(sll_alts):
                perm_str = ''.join(map(str, permutation))
                all_permutations.append(perm_str + '.' + tld)
            if show_debug:
                print("Len of all perms: " + str(len(all_permutations)))

            if len(all_permutations) > parsed_args.max_permutations:
                raise PermutationError(ierr + "Too Many Permutations")

        except PermutationError as e:
            print(ierr + "Too Many Permutations (max-permutations threshold)")
            print(iinfo + "Trying simpler algorithm (will contain only domains with one modified character)")
            all_permutations = get_simple_permutations(sll, tld, lang_code)

        except MemoryError:
            print(ierr + "Too Many Permutations (insufficient memory)")
            print(iinfo + "Trying simpler algorithm (will contain only domains with one modified character)")
            all_permutations = get_simple_permutations(sll, tld, lang_code)

    return all_permutations


def get_simple_permutations(sll, tld, lang_code='none'):
    all_permutations = []
    idx = 0
    for c in sll:
        for altc in alt_chars(c, tld, lang_code):
            newperm = sll[:idx] + chr(int(altc)) + sll[idx + 1:]  # replace original with altchar
            all_permutations.append(newperm + '.' + tld)
        idx += 1
    return all_permutations


# Class that holds and generates typo permutations
class Typo():
    def __init__(self, fqdn):
        self.domain = Domain(fqdn)
        self.tld = self.domain.tld
        self.sll = self.domain.sll
        self.neighbors = []

    # swap chars next to each other
    def generate_swap(self):
        for i in range(0, len(self.sll) - 1 ):
            # print( self.sll[i:i+2] )
            typodomain = self.sll[0:i] + self.sll[i+1] + self.sll[i] + self.sll[i+2:]
            print(typodomain + "." + self.tld)

    # remove single chars
    def generate_missing(self):
        for i in range(0, len(self.sll) ):
            typodomain = self.sll[0:i] + self.sll[i + 1:]
            print(typodomain + "." + self.tld)

    # double chars
    def generate_double(self):
        for i in range(0, len(self.sll)):
            typodomain = self.sll[0:i] + self.sll[i] + self.sll[i] + self.sll[i + 1:]
            print(typodomain + "." + self.tld)

    # split domain (i.e.   exa.mple.com instead of example.com)
    def generate_split(self):
        for i in range(0, len(self.sll) - 1):
            typodomain = self.sll[i + 1:]
            print(typodomain + "." + self.tld)

    def generate_neighbor(self, keymap):
        if keymap == Typo.KeyMap.QWERTY:
            km_file = "qwerty.csv"
        elif keymap == Typo.KeyMap.QWERTZ:
            km_file = "qwertz.csv"
        elif keymap == Typo.KeyMap.AZERTY:
            km_file = "azerty.csv"
        try:
            with open("keymaps/" + km_file, 'r') as f:
                reader = csv.reader(f)
                self.neighbors = list(reader)
        except FileNotFoundError:
            print(ierr + " Keymap file '" + km_file + "' not found!")
            sys.exit(1)

        for i in range(0, len(self.sll)):
            alts = self.get_neighbors(self.sll[i])

            for h in range(1, len(alts)):
                if alts[h] not in (None, ""):
                    nb = self.sll[:i] + alts[h] + self.sll[i + 1:] + '.' + self.tld
                    print(nb)


    class KeyMap():
        QWERTY = 1
        QWERTZ = 2
        AZERTY = 3

    def get_neighbors(self, char):
        for row in self.neighbors:
            if row[0] == char:
                if show_debug:
                    print(row)
                return row


class InvalidFQDNError(Exception):
    pass


class Domain:
    def __init__(self, fqdn):
        # check if valid fqdn
        if '.' not in fqdn:
            raise InvalidFQDNError("'" + fqdn + "' is not a fqdn.")
        elif fqdn.count('.') > 1:
            raise InvalidFQDNError("'" + fqdn + "' is not a fqdn. Only second-level.tld is supported")

        self.tld = fqdn.rsplit('.')[-1]
        self.sll = fqdn.rsplit('.')[-2]

    def is_supported(self):
        # return true if tld is in supported list
        if self.tld in supported_tlds:
            return True
        else:
            return False

    def check_support(self):
        # check if this domain is supported
        if self.tld in ['ca']:
            print(iwarn + ".ca domain does not allow IDNs with doppelganger chars.")
            print("if example.ca is registered only it's owner can register éxample.ca")
            print("Details: https://cira.ca/assets/Documents/Legal/IDN/faq.pdf")
            sys.exit()
        elif self.tld in ['au', 'nl', 'uk', 'us']:
            print(iwarn + '.' + self.tld + " registry does not support IDN.")
            sys.exit()
        elif not self.is_supported():
            print(ierr + '.' + self.tld + " domains are not supported yet. Sorry.")
            sys.exit()


def checkTypo(fqdn):


    typo = Typo(fqdn)
    print("Swaps:")
    typo.generate_swap()
    print("Missing Chars:")
    typo.generate_missing()
    print("Double Chars:")
    typo.generate_double()
    print("Split Domain:")
    typo.generate_split()
    print("Neighbors:")
    typo.generate_neighbor(typo.KeyMap.QWERTZ)


def checkDoppel(fqdn):
    print("checking " + fqdn)

    # get tld
    # TODO: Build class to check if tld is correct and return tld and sll

    domain = Domain(fqdn)
    tld = domain.tld
    sll = domain.sll

    domain.check_support()

    '''
    TODO: [org] zh, ko
    '''
    lang_codes = { 'org': ['bs','bg','be','mk','ru','sr','uk','da','de','hu','is','lv','lt','pl','es','sv'], 'com': ['latin','lisu'], 'se':['latin']}
    sll_alts = []
    all_permutations = []
    nx_tlds = []
    existing_tlds = []


    '''
    if tld in ['ca']:
        print(iwarn + ".ca domain does not allow IDNs with doppelganger chars.")
        print("if example.ca is registered only it's owner can register éxample.ca")
        print("Details: https://cira.ca/assets/Documents/Legal/IDN/faq.pdf")
        sys.exit()
    elif tld not in supported_tlds:
        print(ierr + tld + " domains are not supported yet. Sorry.")
    '''

    if show_time:
        print("Time start...")
        t_start = datetime.datetime.now()

    if tld in lang_codes:
        print(iinfo + tld + " uses language codes")
        for lc in lang_codes[tld]:
            if show_debug:
                print("Permutations for Lang_Code '" + lc + "':")
            all_permutations += get_permutations(sll, tld, lc)
    else:
        all_permutations = get_permutations(sll, tld)

    if show_debug:
        print("All Permutations: " + str(len(all_permutations)))

    unique_permutations = list(set(all_permutations))
    #unique_permutations = [k for k, _ in itertools.groupby(sorted(all_permutations, key=lambda x: all_permutations.index(x)))]

    if show_time:
        t_end = datetime.datetime.now()
        t_diff = t_end - t_start
        print("Time: " + str(t_diff.total_seconds()) + "s")
        sys.exit()

    num_permutations = len(unique_permutations)
    if show_colors:
        print(Fore.WHITE + Style.BRIGHT + str(num_permutations) + Style.RESET_ALL + " unique combinations with allowed "
                                                                                    "characters for ." + tld +
              " domains exist")
    else:
        print(str(num_permutations) + " unique combinations with allowed characters for ." + tld + " domains exist")

    if show_permutations:
        for p in unique_permutations:
            print(p)

    if parsed_args.output_file:
        print(iinfo + "writing doppelgangers to file...")
        with open(parsed_args.output_file, 'w') as file:
            for perm in unique_permutations:
                file.writelines(perm.encode("idna").decode() + "\n")
        sys.exit()

    if parsed_args.dry_run:
        print(isucc + " doppelgangers for " + fqdn + ":")
        for perm in unique_permutations:
            print(perm, end='')
            print(" - " + perm.encode("idna").decode())
        sys.exit()




    print("Checking DNS...")

    current_num = 0
    for domain in unique_permutations:

        sys.stdout.write("Progress: %d / %d \r" % ((current_num +1), num_permutations))
        sys.stdout.flush()

        pc = domain.encode("idna").decode()
        dr = dns.resolver

        try:
            answers = dr.query(pc, 'A')
            if show_colors:
                print(isucc + "Found " + Style.BRIGHT + domain + Style.RESET_ALL, end='')
            else:
                print(isucc + "Found " + domain, end='')
            print(" IDN: " + pc, end='')

            for rdata in answers:
                print(' Address: ', rdata.address, end='')
            print('')
            existing_tlds.append(pc)


        except dns.resolver.NXDOMAIN:
            #print(" - No such domain %s" % pc)
            nx_tlds.append(pc)

        except dns.resolver.Timeout:
            print(" - Timed out while resolving %s" % pc)
        except dns.exception.DNSException:
            print(" - Unhandled exception")

        current_num += 1
        if parsed_args.timing != 0:
            time.sleep((parsed_args.timing / 1000))


def getcombinations(slllist):

    permutations = list(itertools.product(*slllist))
    return permutations


def alt_chars(c, tld, lang_code='none'):
    r = []

    if tld == 'at':
        # https://www.nic.at/media/files/pdf/IDN_Zeichentabelle.pdf
        if c == 'a':
            r = [0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6]
        elif c == 'b':
            r = [0x00fe]
        elif c == 'c':
            r = [0x00e7]
        elif c == 'd':
            r = [0x00f0]
        elif c == 'e':
            r = [0x00e6, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x0153]
        elif c == 'i':
            r = []
        elif c == 'n':
            r = [0x00f1]
        elif c == 'o':
            r = [0x00f0, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f8, 0x0153]
        elif c == 's':
            r = [0x0161]
        elif c == 'u':
            r = [0x00f9, 0x00fa, 0x00fb, 0x00fc]
        elif c == 'y':
            r = [0x00fd]
        elif c == 'z':
            r = [0x017e]
        else:
            r = []

    if tld == 'se':
        #  Source: https://www.iis.se/docs/teckentabell-04.pdf

        if lang_code == 'latin':  # Latin - source: https://www.iis.se/docs/teckentabell-04.pdf
            if c == '3':
                r = [0x01ef, 0x0292]
            elif c == 'a':
                r = [0x00e0, 0x00e1, 0x00e2, 0x00e4, 0x00e5, 0x00e6, 0x00ce]
            elif c == 'b':
                r = [0x0fe]
            elif c == 'c':
                r = [0x00e7, 0x0107, 0x010d]
            elif c == 'd':
                r = [0x00f0, 0x0111]
            elif c == 'e':
                r = [0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x011b, 0x0259]
            elif c == 'g':
                r = [0x01e5, 0x01e7]
            elif c == 'i':
                r = [0x00ec, 0x00ed, 0x00ee, 0x00ef, 0x01d0, 0x0142]
            elif c == 'k':
                r = [0x01e9]
            elif c == 'l':
                r = [0x00ec, 0x00ed, 0x0142]
            elif c == 'n':
                r = [0x00f1, 0x0144, 0x014b]
            elif c == 'o':
                r = [0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f8, 0x01d2]
            elif c == 'r':
                r = [0x0159]
            elif c == 's':
                r = [0x015b, 0x0161]
            elif c == 't':
                r = [0x0163, 0x0167]
            elif c == 'u':
                r = [0x00f9, 0x00fa, 0x00fc, 0x00fd, 0x01d4]
            elif c == 'y':
                r = [0x00fd]
            elif c == 'z':
                r = [0x017a, 0x017e]
            else:
                r = []

        elif lang_code == 'hebrew':  # Hebrew - source: https://www.iis.se/docs/teckentabell-04.pdf
            print("error - hebrew support not built in yet :(")
            if c == '':
                r = []

    # if tld == 'be':
        # https://www.dnsbelgium.be/en/domain-name/valid-domain-name

    if tld == 'no':
        # allowed chars for .no domains
        # Source: https://www.norid.no/en/regelverk/navnepolitikk/#link3
        if c == 'a':
            r = [0x00e0, 0x00e1, 0x00e4, 0x00e5, 0x00e6]
        elif c == 'c':
            r = [0x00e7, 0x010d]
        elif c == 'd':
            r = [0x0111]
        elif c == 'e':
            r = [0x00e6, 0x00e8, 0x00e9, 0x00ea]
        elif c == 'n':
            r = [0x00f1, 0x0144, 0x014b]
        elif c == 'o':
            r = [0x00f2, 0x00f3, 0x00f4, 0x00f6, 0x00f8]
        elif c == 's':
            r = [0x0161]
        elif c == 't':
            r = [0x0167]
        elif c == 'u':
            r = [0x00fc]
        elif c == 'z':
            r = [0x017e]
        else:
            r = []

    if tld == 'dk':
        # allowed chars for .dk domains
        # Source: https://www.dk-hostmaster.dk/en/faqs/what-characters-can-i-use-domain-name
        if c == 'a':
            r = [0x00e4, 0x00e5, 0x00e6]
        elif c == 'e':
            r = [0x00e6, 0x00e9]
        elif c == 'o':
            r = [0x00f6, 0x00f8]
        elif c == 'u':
            r = [0x00fc]
        else:
            r = []

    if tld == 'ch':
        # allowed chars for .ch domains
        # Source: https://www.nic.ch/faqs/idn/
        if c == 'a':
            r = [0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e6]
        elif c == 'b':
            r = [0x00fe]
        elif c == 'c':
            r = [0x00e7]
        elif c == 'd':
            r = [0x00f0]
        elif c == 'e':
            r = [0x00e6] + list(range(0x00e8, (0x00eb + 1))) + [0x0153]
        elif c == 'i':
            r = list(range(0x00ec, (0x00ef + 1)))
        elif c == 'n':
            r = [0x00f1]
        elif c == 'o':
            r = [0x00f0] + list(range(0x00f2, (0x00f6 + 1))) + [0x00f8, 0x0153]
        elif c == 'p':
            r = [0x00fe]
        elif c == 'u':
            r = list(range(0x00f9, (0x00fc + 1)))
        elif c == 'y':
            r = [0x00fd, 0x00ff]
        else:
            r = []

    if tld == 'de':
        # allowed chars for .de domains
        # Source: https://www.denic.de/wissen/idn-domains/idn-zeichenliste/
        if c == 'a':
            r = list(range(0x00e0,  (0x00e6 + 1))) + [0x0101, 0x0103, 0x0105]
        elif c == 'b':
            r = [0x00df, 0x00fe]
        elif c == 'c':
            r = [0x00e7, 0x0107, 0x0109, 0x010B, 0x010D]
        elif c == 'd':
            r = [0x010f, 0x0111]
        elif c == 'e':
            r = [0x00e6, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x0113, 0x0115, 0x0117, 0x019, 0x011b, 0x0153]
        elif c == 'f':
            r = [0x0155]
        elif c == 'g':
            r = [0x011d, 0x011f, 0x0121, 0x0123]
        elif c == 'h':
            r = [0x0125, 0x0127]
        elif c == 'i':
            r = list(range(0x00ec, (0x00ef + 1))) + [0x0129, 0x012b, 0x012d, 0x012f, 0x0131]
        elif c == 'j':
            r = [0x012f, 0x0135]
        elif c == 'k':
            r = [0x0137, 0x0138]
        elif c == 'l':
            r = [0x013a, 0x013c, 0x013e, 0x0142]
        elif c == 'n':
            r = [0x00f1, 0x0144, 0x0146, 0x0148, 0x014b]
        elif c == 'o':
            r = [0x00f0] + list(range(0x00f2, (0x00f6 + 1))) + [0x00f8, 0x014d, 0x014f, 0x0151, 0x0153]
        elif c == 'p':
            r = [0x00fe]
        elif c == 'r':
            r = [0x0155, 0x0157, 0x0159]
        elif c == 's':
            r = [0x00df, 0x015b, 0x015d, 0x015f, 0x0161]
        elif c == 't':
            r = [0x0163, 0x0165, 0x0167]
        elif c == 'u':
            r = list(range(0x00f9, (0x00fc + 1))) + [0x0169, 0x016b, 0x016d, 0x016f, 0x0171, 0x0173]
        elif c == 'w':
            r = [0x0175]
        elif c == 'y':
            r = [0x00fd, 0x00ff, 0x0177]
        elif c == 'z':
            r = [0x017a, 0x017c, 0x017e]
        else:
            r = []

    if tld in ['fr','re','pm','wf','tf','yt']:
        # allowed chars for AFNIC controlled domains
        # Source: https://www.afnic.fr/en/products-and-services/services/idn-convertor/
        if c == 'a':
            r = [0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e6]
        elif c == 'b':
            r = [0x00fe]
        elif c == 'c':
            r = [0x00e7]
        elif c == 'e':
            r = [0x00e6] + list(range(0x00e8, (0x00eb + 1))) + [0x0153]
        elif c == 'i':
            r = list(range(0x00ec, (0x00ef + 1)))
        elif c == 'n':
            r = [0x00f1]
        elif c == 'o':
            r = [0x00f0] + list(range(0x00f2, (0x00f6 + 1))) + [0x00f8, 0x0153]
        elif c == 'u':
            r = list(range(0x00f9, (0x00fc + 1)))
        elif c == 'y':
            r = [0x00fd, 0x00ff]
        else:
            r = []

    if tld == 'org':
        if lang_code == 'is':  # Icelandic - source: http://de.pir.org/pdf/idn/policy_form_is-1.pdf
            if c == 'a':
                r = [0x00e1, 0x00e6]
            elif c == 'b':
                r = [0x00fe]
            elif c == 'e':
                r = [0x00e6, 0x00e9]
            elif c == 'i':
                r = [0x00ed]
            elif c == 'o':
                r = [0x00f0, 0x00f3, 0x00f6]
            elif c == 'p':
                r = [0x00fe]
            elif c == 'u':
                r = [0x00fa]
            elif c == 'y':
                r = [0x00fd]
            else:
                r = []

        elif lang_code == 'de':  # German - source: http://de.pir.org/pdf/idn/policy_form_de.pdf
            if c == 'a':
                r = [0x00e4]
            elif c == 'o':
                r = [0x00f6]
            elif c == 'u':
                r = [0x00fc]
            else:
                r = []

        elif lang_code == 'da':  # Danish - source: http://de.pir.org/pdf/idn/policy_form_da.pdf
            if c == 'a':
                r = [0x00e4, 0x00e5, 0x00e6]
            elif c == 'e':
                r = [0x00e6, 0x00e9]
            elif c == 'o':
                r = [0x00f6, 0x00f8]
            elif c == 'u':
                r = [0x00fc]
            else:
                r = []

        elif lang_code == 'lv':  # Latvian - source: http://de.pir.org/pdf/idn/policy_form_lv.pdf
            if c == 'a':
                r = [0x0101]
            elif c == 'c':
                r = [0x010d]
            elif c == 'e':
                r = [0x0113]
            elif c == 'g':
                r = [0x0123]
            elif c == 'i':
                r = [0x012b]
            elif c == 'k':
                r = [0x0137]
            elif c == 'l':
                r = [0x013c]
            elif c == 'n':
                r = [0x0146]
            elif c == 'o':
                r = [0x014d]
            elif c == 'r':
                r = [0x0157]
            elif c == 's':
                r = [0x0161]
            elif c == 'u':
                r = [0x016b]
            elif c == 'z':
                r = [0x017e]
            else:
                r = []

        elif lang_code == 'lt':  # Lithuanian - source: http://de.pir.org/pdf/idn/policy_form_lt-1.pdf
            if c == 'a':
                r = [0x0105]
            elif c == 'c':
                r = [0x010d]
            elif c == 'e':
                r = [0x0117, 0x0119]
            elif c == 'i':
                r = [0x012f]
            elif c == 'j':
                r = [0x012f]
            elif c == 's':
                r = [0x0161]
            elif c == 'u':
                r = [0x016b, 0x0173]
            elif c == 'z':
                r = [0x017e]
            else:
                r = []

        elif lang_code == 'es':  # Spanish - source: http://de.pir.org/pdf/idn/policy_form_es.pdf
            if c == 'a':
                r = [0x00e1]
            elif c == 'e':
                r = [0x00e9]
            elif c == 'i':
                r = [0x00ed]
            elif c == 'n':
                r = [0x00f1]
            elif c == 'o':
                r = [0x00f3]
            elif c == 'u':
                r = [0x00fa, 0x00fc]
            else:
                r = []

        elif lang_code == 'sv':  # Swedish - source: http://de.pir.org/pdf/idn/policy_form_sv.pdf
            if c == 'a':
                r = [0x00e4, 0x00e5]
            elif c == 'e':
                r = [0x00e9]
            elif c == 'o':
                r = [0x00f6]
            elif c == 'u':
                r = [0x00fc]
            else:
                r = []

        elif lang_code == 'pl':  # Polish - source: http://de.pir.org/pdf/idn/policy_form_pl.pdf
            if c == 'a':
                r = [0x0105]
            elif c == 'c':
                r = [0x0107]
            elif c == 'e':
                r = [0x0119]
            elif c == 'l':
                r = [0x0142]
            elif c == 'n':
                r = [0x0144]
            elif c == 'o':
                r = [0x00f3]
            elif c == 'r':
                r = [0x0157]
            elif c == 's':
                r = [0x015b]
            elif c == 'z':
                r = [0x017a, 0x017c]
            else:
                r = []

        elif lang_code == 'hu':  # Spanish - source: http://de.pir.org/pdf/idn/policy_form_hu.pdf
                if c == 'a':
                    r = [0x00e1]
                elif c == 'e':
                    r = [0x00e9]
                elif c == 'i':
                    r = [0x00ed]
                elif c == 'o':
                    r = [0x00f3, 0x00f6, 0x0151]
                elif c == 'u':
                    r = [0x00fa, 0x00fc, 0x0171]
                else:
                    r = []

        elif lang_code in ['bs', 'bg', 'be', 'mk', 'ru', 'sr', 'uk']:  # Cyrillic - source: https://www.rfc-editor.org/rfc/pdfrfc/rfc5992.txt.pdf
            # Base Cyrillic
            r = []

            if c == 'a':
                r = [0x0430]
            elif c == 'b':
                r = [0x0431, 0x0432, 0x0444]
            elif c == 'c':
                r = [0x0441]
            elif c == 'd':
                r = [0x0444]
            elif c == 'e':
                r = [0x0435]
            elif c == 'h':
                r = [0x043d]
            elif c == 'k':
                r = [0x0436, 0x043a]
            elif c == 'm':
                r = [0x043c]
            elif c == 'o':
                r = [0x0431, 0x043e]
            elif c == 'p':
                r = [0x0440, 0x0444]
            elif c == 't':
                r = [0x0433, 0x0442]
            elif c == 'x':
                r = [0x0445]
            elif c == 'y':
                r = [0x0443, 0x0447]
            elif c == '3':
                r = [0x0437]

            if lang_code in ['bs','sr']:  # Bosnian and Serbian
                if c == 'h':
                    r += [0x0452, 0x045b]
                elif c == 'j':
                    r += [0x0458]
                elif c == 'u':
                    r += [0x045f]
                elif c == 'y':
                    r += [0x045f]
                else:
                    r = []

            if lang_code == 'bg':  # Bulgarian
                if c == 'b':
                    r += [0x044a, 0x044c]
                else:
                    r = []

            if lang_code == 'be': # Belarusian
                if c == 'b':
                    r += [0x044c]
                elif c == 'e':
                    r += [0x0451]
                elif c == 'i':
                    r += [0x0456]
                elif c == 'y':
                    r += [0x045e]
                else:
                    r = []

            if lang_code == 'mk':  # Macedonian
                if c == 'h':
                    r += [0x0452]
                elif c == 'j':
                    r += [0x0458]
                elif c == 'k':
                    r += [0x045c]
                elif c == 's':
                    r += [0x0455]
                elif c == 'u':
                    r += [0x045f]
                elif c == 'y':
                    r += [0x045f]
                else:
                    r = []

            if lang_code == 'ru':  # Russian
                if c == 'b':
                    r += [0x044a, 0x044c]
                elif c == 'e':
                    r += [0x0451]
                else:
                    r = []

            if lang_code == 'uk':  # Ukrainian
                if c == 'b':
                    r += [0x044a, 0x044c]
                elif c == 'e':
                    r += [0x0451]
                elif c == 'i':
                    r += [0x0456, 0x0457]
                else:
                    r = []

        # TODO: Korean ( https://www.iana.org/domains/idn-tables/tables/kr_ko-kr_1.0.html )

        # TODO: Chinese ( https://www.iana.org/domains/idn-tables/tables/cn_zh-cn_4.0.html,
                    # https://www.iana.org/domains/idn-tables/tables/tw_zh-tw_4.0.html )

    if tld in ['com', 'net']:

        if lang_code == 'latin':
            if c == '0':
                r = [0x0298]

            elif c == '2':
                r = [0x01bb]

            elif c == '3':
                r = [0x01ba, 0x01ef, 0x021d, 0x025c, 0x025d, 0x0292, 0x0293, 0x1d08, 0x1d23, 0x1d94, 0x1d9a]

            elif c == '4':
                r = [0xa72d, 0xa72f]

            elif c == '5':
                r = [0x01bd]

            elif c == '6':
                r = [0x1efd]

            elif c == '8':
                r = [0x0223, 0x1d15]

            elif c == 'a':
                r = [0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x0101, 0x0103, 0x0105, 0x01ce, 0x01dd,
                     0x01df, 0x01e1, 0x01e3, 0x01fb, 0x01fd, 0x0201, 0x0203, 0x0227, 0x0251, 0x1d00, 0x1d8f, 0x1e01,
                     0x1ea1, 0x1ea3, 0x1ea5, 0x1ea7, 0x1ea9, 0x1eab, 0x1ead, 0x1eaf,
                     0x1eb1, 0x1eb3, 0x1eb5, 0x1eb7, 0x2c65]

            elif c == 'b':
                r = [0x00df, 0x00fe, 0x0180, 0x0183, 0x0185, 0x0238, 0x0253, 0x0299, 0x1d03, 0x1d6c, 0x1d77, 0x1d80,
                     0x1e03, 0x1e05, 0x1e07]

            elif c == 'c':
                r = [0x00e7, 0x0107, 0x0109, 0x010b, 0x010d, 0x0188, 0x023c, 0x0255, 0x0297, 0x1d04, 0x1e09]

            elif c == 'd':
                r = [0x010f, 0x0111, 0x018c, 0x0221, 0x0238, 0x0256, 0x0257, 0x02a0, 0x1d05, 0x1d06, 0x1d6d, 0x1d81,
                     0x1d91, 0x1e0b, 0x1e0d, 0x1e0f, 0x1e11, 0x1e13, 0x1e9f]

            elif c == 'e':
                r = [0x00e6, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x0113, 0x0115, 0x0117, 0x0119, 0x011b, 0x0153, 0x01e3,
                     0x01fd, 0x0205, 0x0207, 0x0229, 0x0247, 0x025e, 0x0276, 0x1d07, 0x1d92, 0x1e15, 0x1e17, 0x1e19,
                     0x1e1b, 0x1e1d, 0x1eb9, 0x1ebb, 0x1ebd, 0x1ebf, 0x1ec1, 0x1ec3,
                     0x1ec5, 0x1ec7, 0x2c78]

            elif c == 'f':
                r = [0x0192, 0x01ad, 0x0283, 0x0284, 0x1d6e, 0x1d82, 0x1d98, 0x1e1f, 0x1e9c, 0x1e9d, 0xa730, 0xa77c]

            elif c == 'g':
                r = [0x011d, 0x011f, 0x0121, 0x0123, 0x018d, 0x01e5, 0x01e7, 0x01f5, 0x0260, 0x0261, 0x0262, 0x029b,
                     0x1d83, 0x1e21]

            elif c == 'h':
                r = [0x0125, 0x0127, 0x0195, 0x021f, 0x0266, 0x0267, 0x029c, 0x1e23, 0x1e25, 0x1e27, 0x1e29, 0x1e2b,
                     0x1e96, 0x2c68, 0xa727]

            elif c == 'i':
                r = [0x00ec, 0x00ed, 0x00ee, 0x00ef, 0x0129, 0x012b, 0x012d, 0x012f, 0x0131, 0x01d0, 0x0209, 0x020b,
                     0x0268, 0x0269, 0x026a, 0x1d7b, 0x1d96, 0x1e2d, 0x1e2f, 0x1ec9, 0x1ecb, 0xa7fe]

            elif c == 'j':
                r = [0x012f, 0x0135, 0x01f0, 0x0237, 0x0249, 0x025f, 0x0269, 0x026d, 0x027a, 0x0283, 0x0284, 0x029d,
                     0x1d0a, 0x1d96, 0x1d98]

            elif c == 'k':
                r = [0x0137, 0x0138, 0x0199, 0x01e9, 0x1d0b, 0x1d84, 0x1e31, 0x1e33, 0x1e35, 0x2c6a]

            elif c == 'l':
                r = [0x0131, 0x013a, 0x013c, 0x013e, 0x0142, 0x019a, 0x01aa, 0x01c0, 0x01c2, 0x0234, 0x026b, 0x026c,
                     0x026d, 0x027b, 0x0285, 0x0286, 0x029f, 0x1d0c, 0x1d7c, 0x1d85, 0x1e37, 0x1e39, 0x1e3b, 0x1e3d,
                     0x2c61, 0xa7fe]

            elif c == 'm':
                r = [0x0271, 0x028d, 0x1d0d, 0x1d6f, 0x1d86, 0x1e3f, 0x1e41, 0x1e43, 0xa733]

            elif c == 'n':
                r = [0x00f1, 0x0144, 0x0146, 0x0148, 0x014b, 0x019e, 0x01f9, 0x0235, 0x0272, 0x0273, 0x0274, 0x1d70,
                     0x1d87, 0x1e45, 0x1e47, 0x1e49, 0x1e4b, 0xa783, 0xa791]

            elif c == 'o':
                r = [0x00f0, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f8, 0x014d, 0x014f, 0x0151, 0x0153, 0x018d,
                     0x01a1, 0x01a3, 0x01d2, 0x01eb, 0x01ff, 0x020d, 0x020f, 0x022b, 0x022d, 0x022f, 0x0231, 0x0251,
                     0x0252, 0x0254, 0x0275, 0x0276, 0x028a, 0x028b, 0x0298, 0x1d0f,
                     0x1d11, 0x1d13, 0x1e4d, 0x1e4f, 0x1e51, 0x1e53, 0x1e9f, 0x1ecd, 0x1ecf, 0x1ed1, 0x1ed3, 0x1ed5,
                     0x1ed7, 0x1ed9, 0x1edb, 0x1edd, 0x1edf, 0x1ee1, 0x1ee3, 0x2c7a, 0xa74b]

            elif c == 'p':
                r = [0x00fe, 0x01a5, 0x01bf, 0x0239, 0x1d18, 0x1d71, 0x1d7d, 0x1d88, 0x1e55, 0x1e57, 0xa783]

            elif c == 'q':
                r = [0x0239, 0x024b, 0x02a0, 0x1d90]

            elif c == 'r':
                r = [0x0155, 0x0157, 0x0159, 0x0211, 0x0213, 0x024d, 0x027c, 0x027d, 0x027e, 0x0280, 0x1d72, 0x1d73,
                     0x1d89, 0x1e59, 0x1e5b, 0x1e5d, 0x1e5f, 0xa785]

            elif c == 's':
                r = [0x015b, 0x015d, 0x015f, 0x0161, 0x01a8, 0x0219, 0x023f, 0x0282, 0x1d74, 0x1d8a, 0x1e61, 0x1e63,
                     0x1e65, 0x1e67, 0x1e69, 0xa731]

            elif c == 't':
                r = [0x0163, 0x0165, 0x0167, 0x019a, 0x01ab, 0x01ad, 0x021b, 0x0236, 0x0288, 0x1d1b, 0x1d75, 0x1e6b,
                     0x1e6d, 0x1e6f, 0x1e71, 0x1e97, 0x2c66, 0xa787]

            elif c == 'u':
                r = [0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x0169, 0x016b, 0x016d, 0x016f, 0x0171, 0x0173, 0x01b0, 0x01d4,
                     0x01d6, 0x01d8, 0x01da, 0x01dc, 0x0215, 0x0217, 0x0289, 0x028a, 0x028b, 0x02ae, 0x02af, 0x1d1c,
                     0x1d7e, 0x1d7f, 0x1d99, 0x1e73, 0x1e75, 0x1e77, 0x1e79, 0x1e7b,
                     0x1ee5, 0x1ee7, 0x1ee9, 0x1eeb, 0x1eed, 0x1eef, 0x1ef1]

            elif c == 'v':
                r = [0x1d20, 0x1d8c, 0x1e7d, 0x1e7f, 0x2c71, 0x2c74, 0xa769]

            elif c == 'w':
                r = [0x0175, 0x1d21, 0x1e81, 0x1e83, 0x1e85, 0x1e87, 0x1e89, 0x1e98, 0x2c73, 0xa7fd, 0xa7ff]

            elif c == 'x':
                r = [0x1d8d, 0x1e8b, 0x1e8d]

            elif c == 'y':
                r = [0x00fd, 0x00ff, 0x0173, 0x0177, 0x01b4, 0x0233, 0x024f, 0x0263, 0x0264, 0x0265, 0x028f, 0x02ae,
                     0x02af, 0x1d99, 0x1e8f, 0x1e99, 0x1ef3, 0x1ef5, 0x1ef7, 0x1ef9, 0x1eff, 0xa769]

            elif c == 'z':
                r = [0x017a, 0x017c, 0x017e, 0x01b6, 0x0225, 0x0240, 0x0290, 0x0291, 0x1d22, 0x1d24, 0x1d76, 0x1d8e,
                     0x1e91, 0x1e93, 0x1e95, 0x2c6c]

        elif lang_code == 'none':
            if c == 'a':
                r = [0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x0101, 0x0103, 0x0105, 0x01ce, 0x01df,
                     0x01e1,
                     0x01e3, 0x01fb]
            elif c == 'b':
                r = [0x0180] + list(range(0x0182, 0x0185))
                # r = [0x0180,0x0182,0x0183,0x0184]
            elif c == 'c':
                r = [0x00e7, 0x0107, 0x0109, 0x010B, 0x010D, 0x0188]
            elif c == 'd':
                r = [0x010f, 0x0111, 0x018b, 0x018c]
            elif c == 'e':
                r = range(0x00e8, 0x00ef) + [0x0113, 0x0115, 0x0117, 0x0119, 0x011b, 0x0153, 0x018f, 0x019e, 0x01dd]
            elif c == 'f':
                r = [0x017f, 0x0192]
            elif c == 'g':
                r = [0x011d, 0x0111f, 0x0121, 0x0123, 0x01e5, 0x01e7, 0x01f5]
            elif c == 'h':
                r = [0x0125, 0x0127, 0x0195]
            elif c == 'i':
                r = list(range(0x00ec, 0x00ef)) + [0x0129, 0x012b, 0x012d, 0x012f, 0x0131, 0x0133, 0x01d0, 0x01f0]
            elif c == 'j':
                r = [0x012f, 0x0133, 0x0135, 0x01f0]
            elif c == 'k':
                r = [0x0137, 0x0138, 0x0199, 0x01e9]
            elif c == 'l':
                r = [0x013a, 0x013c, 0x013e, 0x0140, 0x0142, 0x0196, 0x0197, 0x019a, 0x01aa, 0x01ab, 0x01ad]
                # m
            elif c == 'n':
                r = [0x0144, 0x0146, 0x0148, 0x0149, 0x014b, 0x01f9]
            elif c == 'o':
                r = [0x00f0] + list(range(0x00f2, 0x00f6)) + [0x00f8, 0x014d, 0x014f, 0x0151, 0x0153, 0x018d, 0x018f,
                                                              0x019f, 0x01a1,
                                                              0x01a3, 0x01d2, 0x01eb, 0x01ed, 0x01ff]
            elif c == 'p':
                r = [0x01a5, 0x01bf]
                # q
            elif c == 'r':
                r = [0x0155, 0x0157, 0x0159]
            elif c == 's':
                r = [0x015b, 0x015d, 0x015f, 0x0162, 0x01a8]
            elif c == 't':
                r = [0x0163, 0x0165, 0x0167, 0x01ab, 0x01ad]
            elif c == 'u':
                r = list(range(0x00f9, 0x00fc)) + [0x0169, 0x016b, 0x016d, 0x016f, 0x0171, 0x0173, 0x01b0, 0x01b1,
                                                   0x01d4, 0x01d6,
                                                   0x01d8, 0x01da, 0x01dc]
            elif c == 'v':
                r = [0x0152, 0x01bf, 0x01f7]
            elif c == 'w':
                r = [0x0175, 0x019c]
                # x
            elif c == 'y':
                r = [0x00fd, 0x00ff, 0x0177, 0x01b4, 0x01bf, 0x01f7]
            elif c == 'z':
                r = [0x017a, 0x017c, 0x017e, 0x01b6]

        elif lang_code == 'UKR':
            if c == 'a':
                r = [0x0430]
            elif c == 'b':
                r = [0x0431, 0x044c]
            elif c == 'c':
                r = [0x0441, 0x0454]
            elif c == 'e':
                r = [0x0435, 0x0454]
            elif c == 'h':
                r = [0x043d]
            elif c == 'i':
                r = [0x0456, 0x0457]
            elif c == 'k':
                r = [0x043a]
            elif c == 'm':
                r = [0x043c]
            elif c == 'o':
                r = [0x043e, 0x044e]
            elif c == 'p':
                r = [0x0440]
            elif c == 't':
                r = [0x0442]
            elif c == 'u':
                r = [0x0447]
            elif c == 'x':
                r = [0x0436, 0x0445]
            elif c == 'y':
                r = [0x0443, 0x0447]

    return r


if __name__ == '__main__':
    import sys

    sys.exit(main(sys.argv))
