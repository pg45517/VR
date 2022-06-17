from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import info
from mininet.log import setLogLevel
from mininet.link import TCLink
from subprocess import call
import time

    #"Topology Exercise 2"

def Topology():
    #"Create custom topo."

    info('Net A -> 192.168.1.0/24\nNet B -> 192.168.2.0/24\nNet C -> 192.168.3.0/24\n')

    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSSwitch )

    info('***Creating remote controller on port 6633 (L2 switches)\n')
    c0 = net.addController(name='c0',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6633)
    
    info('***Creating remote controller on port 6655 (L3 switch)\n')
    c1 = net.addController(name='c1',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6655)

    info('Adding L3 switch\n')
    r1 = net.addSwitch('r1', cls = OVSSwitch, dpid = '0000000000000001')  # L3 switch
    r2 = net.addSwitch('r2', cls = OVSSwitch, dpid = '0000000000000002')  # L3 switch
    r3 = net.addSwitch('r3', cls = OVSSwitch, dpid = '0000000000000003')  # L3 switch

    info('Adding L2 switches\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, dpid='0000000000000004') # L2 Switch Net B (no ip)
    s2 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000005') # L2 Switch Net C (no ip)
    s3 = net.addSwitch('s3', cls=OVSSwitch, dpid='0000000000000006') # L2 Switch Net C (no ip)
        

    info('Add hosts and switches\n')
    h1 = net.addHost( 'h1', ip = '191.0.0.1/24', mac = '00:00:00:00:00:01', defaultRoute='via 191.0.0.254')   # Host 1 Net R&D
    h2 = net.addHost( 'h2', ip = '191.0.0.2/24', mac = '00:00:00:00:00:02', defaultRoute='via 191.0.0.254' )   # Host 2 Net R&D
    h3 = net.addHost( 'h3', ip = '191.0.0.3/24', mac = '00:00:00:00:00:03', defaultRoute='via 191.0.0.254' )   # Http server Net R&D
    h4 = net.addHost( 'h4', ip = '192.0.0.1/24', mac = '00:00:00:00:00:04', defaultRoute='via 192.0.0.254' )   # Host 1 Net Client Support
    h5 = net.addHost( 'h5', ip = '192.0.0.2/24', mac = '00:00:00:00:00:05', defaultRoute='via 192.0.0.254' )   # Host 2 Net Client Support
    h6 = net.addHost( 'h6', ip = '192.0.0.3/24', mac = '00:00:00:00:00:06', defaultRoute='via 192.0.0.254' )   # Host 3 Net Client Support
    h7 = net.addHost( 'h7', ip = '193.0.0.1/24', mac = '00:00:00:00:00:07', defaultRoute='via 193.0.0.254' )   # Host 1 Net Executive
    h8 = net.addHost( 'h8', ip = '193.0.0.2/24', mac = '00:00:00:00:00:08', defaultRoute='via 193.0.0.254' )   # Host 2 Net Executive
    h9 = net.addHost( 'h9', ip = '193.0.0.3/24', mac = '00:00:00:00:00:09', defaultRoute='via 193.0.0.254' )   # Host 3 Net Executive
    
    info('Adding links Net A (R&H Division)\n')
    net.addLink( h1, s1 )
    net.addLink( h2, s1 )
    net.addLink( h3, s1 )
    net.addLink( r1, s1 )

    info('\nAdding links Net B (Client Support Division)\n')
    net.addLink( h4, s2 )
    net.addLink( h5, s2 )
    net.addLink( h6, s2 )
    net.addLink( r2, s2 )

    info('\nAdding links Net C (Executive Division)\n')
    net.addLink( h7, s3 )
    net.addLink( h8, s3 )
    net.addLink( h9, s3 )
    net.addLink( r3, s3 )

    info('\nAdding links among L3 switches\n')
    net.addLink(r1,r2)
    net.addLink(r1,r3, cls=TCLink, delay = '5ms')
    net.addLink(r2,r3)

    info('Setting MAC addresses to switches')
    s1.setMAC('10:00:00:00:00:01', 's1-eth1')
    s1.setMAC('10:00:00:00:00:02', 's1-eth2')
    s1.setMAC('10:00:00:00:00:03', 's1-eth3')
    s1.setMAC('10:00:00:00:00:04', 's1-eth4')
    s2.setMAC('20:00:00:00:00:01', 's2-eth1')
    s2.setMAC('20:00:00:00:00:02', 's2-eth2')
    s2.setMAC('20:00:00:00:00:03', 's2-eth3')
    s2.setMAC('20:00:00:00:00:04', 's2-eth4')
    s3.setMAC('30:00:00:00:00:01', 's3-eth1')
    s3.setMAC('30:00:00:00:00:02', 's3-eth2')
    s3.setMAC('30:00:00:00:00:03', 's3-eth3')
    s3.setMAC('30:00:00:00:00:04', 's3-eth4')
    r1.setMAC('00:00:00:00:00:11', 'r1-eth1')
    r1.setMAC('00:00:00:00:00:12', 'r1-eth2')
    r1.setMAC('00:00:00:00:00:13', 'r1-eth3')
    r2.setMAC('00:00:00:00:00:21', 'r2-eth1')
    r2.setMAC('00:00:00:00:00:22', 'r2-eth2')
    r2.setMAC('00:00:00:00:00:23', 'r2-eth3')
    r3.setMAC('00:00:00:00:00:31', 'r3-eth1')
    r3.setMAC('00:00:00:00:00:32', 'r3-eth2')
    r3.setMAC('00:00:00:00:00:33', 'r3-eth3')


    net.build()

    # Switches
    r1.start([c1])
    r2.start([c1])
    r3.start([c1])
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    info('\nSetting up of IP addresses in the R1\n')
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth2 0")
    r1.cmd("ifconfig r1-eth3 0")
    r1.cmd("ip addr add 191.0.0.254/24 brd + dev r1-eth1") # Link R1-S1
    r1.cmd("ip addr add 12.0.0.253/24 brd + dev r1-eth2") # Link R1-R2
    r1.cmd("ip addr add 13.0.0.253/24 brd + dev r1-eth3") # Link R1-R3
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    info('\nSetting up of IP addresses in the R2\n')
    r2.cmd("ifconfig r2-eth1 0")
    r2.cmd("ifconfig r2-eth2 0")
    r2.cmd("ifconfig r2-eth3 0")
    r2.cmd("ip addr add 192.0.0.254/24 brd + dev r2-eth1") # Link R2-S2
    r2.cmd("ip addr add 12.0.0.254/24 brd + dev r2-eth2") # Link R1-R2
    r2.cmd("ip addr add 23.0.0.253/24 brd + dev r2-eth3") # Link R2-R3
    r2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    info('\nSetting up of IP addresses in the R3\n')
    r3.cmd("ifconfig r3-eth1 0")
    r3.cmd("ifconfig r3-eth2 0")
    r3.cmd("ifconfig r3-eth3 0")
    r3.cmd("ip addr add 193.0.0.254/24 brd + dev r3-eth1") # Link R3-S3
    r3.cmd("ip addr add 13.0.0.254/24 brd + dev r3-eth2") # Link R1-R3
    r3.cmd("ip addr add 23.0.0.254/24 brd + dev r3-eth3") # Link R2-R3
    r3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    info('Setting GW to hosts\n')
    h1.cmd("ip route add default via 191.0.0.254")  # GW Net R&D
    h2.cmd("ip route add default via 191.0.0.254")  # GW Net R&D
    h3.cmd("ip route add default via 191.0.0.254")  # GW Net R&D
    h4.cmd("ip route add default via 192.0.0.254")  # GW Net Client Support
    h5.cmd("ip route add default via 192.0.0.254")  # GW Net Client Support
    h6.cmd("ip route add default via 192.0.0.254")  # GW Net Client Support
    h7.cmd("ip route add default via 193.0.0.254")  # GW Net Executive
    h8.cmd("ip route add default via 193.0.0.254")  # GW Net Executive
    h9.cmd("ip route add default via 193.0.0.254")  # GW Net Executive

    info('GW Net R&D -> 191.0.0.254/24\nGW Net Client Support -> 192.0.0.254/24\nGW Net Executive -> 193.0.0.254/24\n')
    info('sudo mn --controller=remote,ip=127.0.0.1,port=6655 (L3 CONTROLLER)\n')
    info('sudo mn --controller=remote,ip=127.0.0.1,port=6633 (L2 CONTROLLER)\n')
        
    # Start command line
    CLI(net)

    # Stop Network
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    Topology()