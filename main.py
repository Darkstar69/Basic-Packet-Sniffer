#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules import *
from colorama import Fore, Style
from art import *

def banner():
    tprint("snifPy", font="random")
    
def main():
    banner()
    count2capture = int(input("Enter number of packets to capture : "))
    sniffer(count2capture)

if __name__ == "__main__":
    try:
        main()
    except:
        print("\nSome Error Occured\nBye!!")