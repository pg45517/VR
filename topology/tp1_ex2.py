#!/usr/bin/python

import sys

from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi


def myNetwork():

    net = Mininet_wifi(controller=None)
    #net = Mininet(switch=OVSSwitch,controller=RemoteController, autoStaticArp=True)

    info('*** Adicionando o Controlador\n' )
    c1 = RemoteController('c1', ip='127.0.0.1', port=6653)
    net.addController(c1)

    info('*** Add switches/APs\n')
    s1 = net.addSwitch('s1', mac='00:00:00:00:01:01')
    s2 = net.addSwitch('s2', mac='00:00:00:00:01:02')
    s3 = net.addSwitch('s3', mac='00:00:00:00:01:03')
    r1 = net.addSwitch('r1', mac='10:00:00:00:00:01' )  # L3 switch
    

    info('Add hosts and switches\n')
    h1_A = net.addHost( 'h1_A', ip = '192.168.1.1/24', mac = '00:00:00:00:00:01', defaultRoute='via 192.168.1.254')    # Host 1 Net A
    h2_A = net.addHost( 'h2_A', ip = '192.168.1.2/24', mac = '00:00:00:00:00:02', defaultRoute='via 192.168.1.254' )   # Host 2 Net A
    h3_A = net.addHost( 'h3_A', ip = '192.168.1.3/24', mac = '00:00:00:00:00:03', defaultRoute='via 192.168.1.254' )   # Host 3 Net A
    h1_B = net.addHost( 'h1_B', ip = '192.168.2.1/24', mac = '00:00:00:00:00:04', defaultRoute='via 192.168.2.254' )   # Host 1 Net B
    h2_B = net.addHost( 'h2_B', ip = '192.168.2.2/24', mac = '00:00:00:00:00:05', defaultRoute='via 192.168.2.254' )   # Host 2 Net B
    h3_B = net.addHost( 'h3_B', ip = '192.168.2.3/24', mac = '00:00:00:00:00:06', defaultRoute='via 192.168.2.254' )   # Host 3 Net B
    h1_C = net.addHost( 'h1_C', ip = '192.168.3.1/24', mac = '00:00:00:00:00:07', defaultRoute='via 192.168.3.254' )   # Host 1 Net C
    h2_C = net.addHost( 'h2_C', ip = '192.168.3.2/24', mac = '00:00:00:00:00:08', defaultRoute='via 192.168.3.254' )   # Host 2 Net C
    h3_C = net.addHost( 'h3_C', ip = '192.168.3.3/24', mac = '00:00:00:00:00:09', defaultRoute='via 192.168.3.254' )   # Host 3 Net C
    
   
    info('Adding links Net A\n')
    net.addLink( h1_A, s1 )
    net.addLink( h2_A, s1 )
    net.addLink( h3_A, s1 )
    net.addLink( r1, s1, cls=TCLink, delay = '5ms' )

    info('\nAdding links Net B\n')
    net.addLink( h1_B, s2 )
    net.addLink( h2_B, s2 )
    net.addLink( h3_B, s2, cls=TCLink, delay = '5ms' )
    net.addLink( r1, s2 )

    info('\nAdding links Net C\n')
    net.addLink( h1_C, s3 )
    net.addLink( h2_C, s3 )
    net.addLink( h3_C, s3, cls=TCLink, losses = '10')
    net.addLink( r1, s3 )

    info('*** Iniciando a Rede\n')
    net.build()
    
    info('*** Iniciando o Controlador\n')
    c1.start()

    info('*** Iniciando os switches\n')
    s1.start([c1])
    s2.start([c1])
    s3.start([c1])
    

    info('\nSetting up of IP addresses in the R1\n')
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth2 0")
    r1.cmd("ifconfig r1-eth3 0")
    r1.cmd("ip addr add 192.168.1.254/24 brd + dev r1-eth1")
    r1.cmd("ip addr add 192.168.2.254/24 brd + dev r1-eth2")
    r1.cmd("ip addr add 192.168.3.254/24 brd + dev r1-eth3")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
  
    info('Setting GW to hosts\n')
    h1_A.cmd("ip route add default via 192.168.1.254")  # GW Net A
    h2_A.cmd("ip route add default via 192.168.1.254")  # GW Net A
    h3_A.cmd("ip route add default via 192.168.1.254")  # GW Net A
    h1_B.cmd("ip route add default via 192.168.2.254")  # GW Net B
    h2_B.cmd("ip route add default via 192.168.2.254")  # GW Net B
    h3_B.cmd("ip route add default via 192.168.2.254")  # GW Net B
    h1_C.cmd("ip route add default via 192.168.3.254")  # GW Net B
    h2_C.cmd("ip route add default via 192.168.3.254")  # GW Net B
    h3_C.cmd("ip route add default via 192.168.3.254")  # GW Net B

    info('GW Net A -> 192.168.1.254/24\nGW Net B -> 192.168.2.254/24\nGW Net C -> 192.168.3.254/24\n')
    #info('sudo mn --controller=remote,ip=127.0.0.1,port=6655\n')
    #info('sudo mn --controller=remote,ip=127.0.
  

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()
