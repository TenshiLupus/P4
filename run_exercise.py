#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI
from mininet.node import OVSController

def run():
	topo = SingleSwitchTopo(k=2)
	net = Mininet(topo, controller=OVSController)
	net.start()
	print("running ping test")
	net.pingAll()
	CLI(net)
	net.stop()

if __name__ == "__main__":
	run()
