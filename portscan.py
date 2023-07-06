import nmap


def bls():
    nm = nmap.PortScanner()
    server = input("Enter Server:")
    if not server.lower().endswith('blacklanternsecurity.com'):
        server = f'{server}.blacklanternsecurity.com'
    print(server)
    result = nm.scan(hosts=server, arguments='-sn')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print(hosts_list)


def main():
    print("#########   #           ###########      ############  ##########")
    print("#        #  #           #                      #       ###     ##")
    print("#        #  #           #                      #       ##########")
    print("##########  #           ###########            #       #")
    print("#        #  #                     #            #       #")
    print("#        #  #                     #            #       #")
    print("#########   ##########  ###########      ############  #")
    while True:
        bls()


if __name__ == "__main__":
    main()