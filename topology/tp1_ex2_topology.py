from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.link import TCLink
from subprocess import call

def Topology():
    info("Creating TP1 Exercise 2 topology...")
    info('Net A -> 192.168.1.0/24\nNet B -> 192.168.2.0/24\nNet C -> 192.168.3.0/24\n')

    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSSwitch )

    info('***Connecting to remote controller on port 6633 (L2 switches)\n')
    c0 = net.addController(name='c0',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6633)
    
    info('***Connectig to remote controller on port 6655 (L3 switch)\n')
    c1 = net.addController(name='c1',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6655)

    info('Adding L3 switch\n')
    r1 = net.addSwitch('r1', cls=OVSSwitch, dpid='0000000000000001')  # L3 switch

    info('Adding L2 switches\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, dpid='0000000000000002') # L2 Switch Net B (no ip)
    s2 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000003') # L2 Switch Net C (no ip)
    s3 = net.addSwitch('s3', cls=OVSSwitch, dpid='0000000000000004') # L2 Switch Net C (no ip)
        
    info('Adding hosts and links to switches\n')
    h1_A = net.addHost('h1_A', ip='192.168.1.1/24', mac='00:00:00:00:00:01', defaultRoute='via 192.168.1.254')   # Host 1 Net A
    h2_A = net.addHost('h2_A', ip='192.168.1.2/24', mac='00:00:00:00:00:02', defaultRoute='via 192.168.1.254')   # Host 2 Net A
    h3_A = net.addHost('h3_A', ip='192.168.1.3/24', mac='00:00:00:00:00:03', defaultRoute='via 192.168.1.254')   # Host 3 Net A
    h1_B = net.addHost('h1_B', ip='192.168.2.1/24', mac='00:00:00:00:00:04', defaultRoute='via 192.168.2.254')   # Host 1 Net B
    h2_B = net.addHost('h2_B', ip='192.168.2.2/24', mac='00:00:00:00:00:05', defaultRoute='via 192.168.2.254')   # Host 2 Net B
    h3_B = net.addHost('h3_B', ip='192.168.2.3/24', mac='00:00:00:00:00:06', defaultRoute='via 192.168.2.254')   # Host 3 Net B
    h1_C = net.addHost('h1_C', ip='192.168.3.1/24', mac='00:00:00:00:00:07', defaultRoute='via 192.168.3.254')   # Host 1 Net C
    h2_C = net.addHost('h2_C', ip='192.168.3.2/24', mac='00:00:00:00:00:08', defaultRoute='via 192.168.3.254')   # Host 2 Net C
    h3_C = net.addHost('h3_C', ip='192.168.3.3/24', mac='00:00:00:00:00:09', defaultRoute='via 192.168.3.254')   # Host 3 Net C
    
    info('Adding links Net A\n')
    net.addLink(h1_A, s1)
    net.addLink(h2_A, s1)
    net.addLink(h3_A, s1)
    net.addLink(r1, s1, cls=TCLink, delay='5ms')

    info('Adding links Net B\n')
    net.addLink(h1_B, s2)
    net.addLink(h2_B, s2)
    net.addLink(h3_B, s2, cls=TCLink, delay='5ms')
    net.addLink(r1, s2)

    info('Adding links Net C\n')
    net.addLink(h1_C, s3)
    net.addLink(h2_C, s3)
    net.addLink(h3_C, s3, cls=TCLink, loss=10)
    net.addLink(r1, s3)

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
    r1.setMAC('40:00:00:00:00:01', 'r1-eth1')
    r1.setMAC('40:00:00:00:00:02', 'r1-eth2')
    r1.setMAC('40:00:00:00:00:03', 'r1-eth3')

    net.build()

    # Starting switches
    r1.start([c1])
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    info('Setting up of IP addresses in the R1\n')
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
        
    # Start command line
    CLI(net)

    # Stop Network
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    Topology()
