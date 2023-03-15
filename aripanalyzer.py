from arbin import *

class Ipanalyzer:
    def __init__(self, ipcidr=''):
        self.bin_worker = Ar_bin()
        ipcidr_lt = ipcidr.split('/')
        self.ipv4 = ipcidr_lt[0]
        self.cidr = ipcidr_lt[1]
        self.masc_bin = self.cidr_to_bin(self.cidr)
        self.masc_dec = self.cidr_to_dec(self.cidr)
        self.get_nhosts_nsubnets()
    
    def show(self):
        print('--'*10)
        print(f'IPV4: {self.ipv4}')
        print(f'CIDR: {self.cidr}')
        print(f'masc bin: {self.masc_bin}')
        print(f'masc dec: {self.masc_dec}')
        print(f'Number of possible nets: {self.n_nets}')
        print(f'Number of possible hosts: {self.n_hosts}')
        print(f'Has subnets: {self.has_subnet}')
        print(f'Number of possible subnets: {self.n_subnets}')
        print('--'*10)

    def ipv4_to_bin(self, ipv4):
        pass
    
    def cidr_to_bin(self, cidr, pts=True):
        n_ones, n_zeros = int(cidr), 32-int(cidr)
        masc_withdout_pts = '1'*n_ones + '0'*n_zeros
        masc_with_pts = masc_withdout_pts[0:8]+'.'+masc_withdout_pts[8:16]+'.'+masc_withdout_pts[16:24]+'.'+masc_withdout_pts[24:32]
        if pts: return masc_with_pts
        return masc_withdout_pts

    def cidr_to_dec(self, cidr):
        masc_bin = self.cidr_to_bin(cidr)
        bins = masc_bin.split('.')
        masc_dec = ''
        for i in bins: masc_dec += str(self.bin_worker.Bin_to_int(i))+'.'
        masc_dec = masc_dec[0:-1]
        return masc_dec
    
    def get_nhosts_nsubnets(self):
        self.has_subnet = bool(int(self.cidr)%8)
        masc_withdout_pts = self.cidr_to_bin(self.cidr, pts=False)
        self.n_nets = 2**(int(self.cidr))
        self.n_hosts = self.bin_worker.Bin_to_int('1'*masc_withdout_pts.count('0')) + 1
        if self.has_subnet:
            if int(self.cidr)==32: x=0
            elif int(self.cidr)<8:x=int(self.cidr)
            elif int(self.cidr)<16:x=int(self.cidr)-8
            elif int(self.cidr)<24:int(self.cidr)-16
            elif int(self.cidr)<32:int(self.cidr)-24
            self.n_subnets = 2**x
        else:
            self.n_subnets = None

def main():
    ipv4 = input('\nIPV4 and CIDR: ')

    ipanalyser1 = Ipanalyzer(ipv4)
    ipanalyser1.show()

if __name__ == '__main__':
    main()
