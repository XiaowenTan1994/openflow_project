from mininet.topo import Topo

class part3_topo(Topo):
    def __init__(self):
        Topo.__init__(self)

        host9 = self.addHost('h9', ip='172.17.16.2/24', defaultRoute='via 172.17.16.1')
        host10 = self.addHost('h10', ip='172.17.16.3/24', defaultRoute='via 172.17.16.1')
        host11 = self.addHost('h11', ip='172.17.16.4/24', defaultRoute='via 172.17.16.1')
        host12 = self.addHost('h12', ip='10.0.0.2/25', defaultRoute='via 10.0.0.1')
        host13 = self.addHost('h13', ip='10.0.0.3/25', defaultRoute='via 10.0.0.1')
        host14 = self.addHost('h14', ip='10.0.0.4/25', defaultRoute='via 10.0.0.1')
        host15 = self.addHost('h15', ip='10.0.0.130/25', defaultRoute='via 10.0.0.129')
        host16 = self.addHost('h16', ip='10.0.0.131/25', defaultRoute='via 10.0.0.129')
        host17 = self.addHost('h17', ip='10.0.0.132/25', defaultRoute='via 10.0.0.129')
        host18 = self.addHost('h18', ip='20.0.0.2/25', defaultRoute='via 20.0.0.1')
        host19 = self.addHost('h19', ip='20.0.0.3/25', defaultRoute='via 20.0.0.1')
        host20 = self.addHost('h20', ip='20.0.0.4/25', defaultRoute='via 20.0.0.1')
        host21 = self.addHost('h21', ip='20.0.0.130/25', defaultRoute='via 20.0.0.129')
        host22 = self.addHost('h22', ip='20.0.0.131/25', defaultRoute='via 20.0.0.129')
        host23 = self.addHost('h23', ip='20.0.0.132/25', defaultRoute='via 20.0.0.129')

        router1 = self.addSwitch('r1')
        router2 = self.addSwitch('r2')
        router3 = self.addSwitch('r3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')
        switch6 = self.addSwitch('s6')
        switch7 = self.addSwitch('s7')
        switch8 = self.addSwitch('s8')


        # Add links
        self.addLink('h9', 's4', port1=1, port2=2)
        self.addLink('h10', 's4', port1=2, port2=3)
        self.addLink('h11', 's4', port1=1, port2=4)
        self.addLink('h12', 's5', port1=1, port2=2)
        self.addLink('h13', 's5', port1=1, port2=3)
        self.addLink('h14', 's5', port1=1, port2=4)
        self.addLink('h15', 's6', port1=1, port2=2)
        self.addLink('h16', 's6', port1=1, port2=3)
        self.addLink('h17', 's6', port1=1, port2=4)
        self.addLink('h18', 's7', port1=1, port2=2)
        self.addLink('h19', 's7', port1=1, port2=3)
        self.addLink('h20', 's7', port1=1, port2=4)
        self.addLink('h21', 's8', port1=1, port2=2)
        self.addLink('h22', 's8', port1=1, port2=3)
        self.addLink('h23', 's8', port1=1, port2=4)
        self.addLink('s4', 'r1', port1=1, port2=1)
        self.addLink('s5', 'r2', port1=1, port2=1)
        self.addLink('s6', 'r2', port1=1, port2=2)
        self.addLink('s7', 'r3', port1=1, port2=1)
        self.addLink('s8', 'r3', port1=1, port2=2)
        self.addLink('r1', 'r2', port1=2, port2=3)
        self.addLink('r1', 'r3', port1=3, port2=3)

topos = {'mytopo': (lambda: part3_topo())}