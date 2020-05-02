"""
Three devices on different networks and all connected by a single router

	host --- router ---- host
		   		|
		   		|
		   		|
		  	   host

"""

from mininet.topo import Topo


class s2_Topo(Topo):

	def __init__(self):
		"Create custom topo."
		# Initialize topology
		Topo.__init__(self)

		# Add hosts and switches
		host1 = self.addHost('h1', ip="10.0.0.2/24", defaultRoute="via 10.0.0.1")
		host2 = self.addHost('h2', ip="20.0.0.2/24", defaultRoute="via 20.0.0.1")
		host3 = self.addHost('h3', ip="30.0.0.2/24", defaultRoute="via 30.0.0.1")

		switch = self.addSwitch('s1')

		# Add links
		self.addLink(host1, switch)
		self.addLink(host2, switch)
		self.addLink(host3, switch)


topos = {'mytopo': (lambda: s2_Topo())}