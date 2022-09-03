from arbin import *

class Ar_bin:
    def Int_to_bin(self, Int):
        result = Int
        numero = result
        bin = ''
        while result != 1:
            result = numero//2
            resto = numero%2
            bin = str(resto) + bin
            numero = result
        return str(result) + bin
    
    def Bin_to_int(self, Bin):
        list_num = [int(Bin[i]) for i in range(len(Bin)-1, -1, -1)]
        Int = 0
        for i in range(len(list_num)):
            alg = int(list_num[i])
            pos = i
            op = alg*(2**pos)
            Int += op
        return Int

class Ipanalyzer:
    def __init__(self, ipcidr=''):
        self.bin_worker = Ar_bin()
        ipcidr_lt = ipcidr.split('/')
        self.ipv4 = ipcidr_lt[0]
        self.cidr = ipcidr_lt[1]
        self.masc_bin = self.cidr_to_bin(self.cidr)
        self.masc_dec = self.cidr_to_dec(self.cidr)
        self.hosts_subnets = self.get_nhosts_nsubnets(self.cidr)
    
    def show(self):
        print('--'*10)
        print(f'IPV4: {self.ipv4}')
        print(f'CIDR: {self.cidr}')
        print(f'masc bin: {self.masc_bin}')
        print(f'masc dec: {self.masc_dec}')
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
    
    def get_nhosts_nsubnets(self, cidr):
        self.has_subnet = bool(int(cidr)%8)
        masc_withdout_pts = self.cidr_to_bin(cidr, pts=False)
        self.n_hosts = self.bin_worker.Bin_to_int('1'*masc_withdout_pts.count('0')) + 1
        self.n_subnets = int(256*(256/self.n_hosts))
        if not self.has_subnet: self.n_subnets = None

def main():
    ipv4 = input('\nIPV4 and CIDR: ')

    ipanalyser1 = Ipanalyzer(ipv4)
    ipanalyser1.show()

if __name__ == '__main__':
    main()
