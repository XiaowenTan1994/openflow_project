from mininet.topo import Topo

class part1_topo(Topo):
    def __init__(self):
        Topo.__init__(self)
        host1 = self.addHost('h1', ip="10.0.0.2/24", defaultRoute = "via 10.0.0.1")
        host2 = self.addHost('h2', ip="10.0.0.3/24", defaultRoute = "via 10.0.0.1")
        host3 = self.addHost('h3', ip="10.0.0.4/24", defaultRoute = "via 10.0.0.1")

        switch = self.addSwitch('s1')
        self.addLink(host1, switch)
        self.addLink(host2, switch)
        self.addLink(host3, switch)

topos = {'mytopo':(lambda: part1_topo())}