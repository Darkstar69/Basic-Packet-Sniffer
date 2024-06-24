#!/usr/bin/python3
# -*- coding: utf-8 -*-

from modules import *
from colorama import Fore, Style
from art import *

banner_text = "Sniffy"

def banner():
    tprint(banner_text, font="random")
    
def main():
    banner()
    filename = input("Enter file name : ")
    count2capture = int(input("Enter number of packets to capture : "))
    sniffer(filename, count2capture)

if __name__ == "__main__":
    main()