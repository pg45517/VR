#sudo mn -c &&

from distutils.log import info
from mininet.node import Node
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController



if '__main__' == __name__:
        net = Mininet(controller=RemoteController)

        c0 = net.addController('c0', port=6633)
        c1 = net.addController('c1', port=6653)
        info("*** CREATING NETWORK ***")

        defaultIP = '192.168.0.1/24'


        # Add hosts and switches
        h1_A = net.addHost( 'h1_A', ip = '192.168.1.1/24' )   # Host 1 Net A
        h2_A = net.addHost( 'h2_A', ip = '192.168.1.2/24' )   # Host 2 Net A
        h3_A = net.addHost( 'h3_A', ip = '192.168.1.3/24' )   # Host 3 Net A
        h1_B = net.addHost( 'h1_B', ip = '192.168.2.1/24' )   # Host 1 Net B
        h2_B = net.addHost( 'h2_B', ip = '192.168.2.2/24'  )   # Host 2 Net B
        h3_B = net.addHost( 'h3_B', ip = '192.168.2.3/24'  )   # Host 3 Net B
        h1_C = net.addHost( 'h1_C', ip = '192.168.3.1/24'  )   # Host 1 Net C
        h2_C = net.addHost( 'h2_C', ip = '192.168.3.2/24'  )   # Host 2 Net C
        h3_C = net.addHost( 'h3_C', ip = '192.168.3.3/24'  )   # Host 3 Net C
        s1 = net.addSwitch( 's1' )     # L2 Switch Net A (no ip)
        s2 = net.addSwitch( 's2' )     # L2 Switch Net B (no ip)
        s3 = net.addSwitch( 's3' )     # L2 Switch Net C (no ip)
        r1 = net.addSwitch( 'r1', ip=defaultIP )     # L3 Switch
        


        # Add links
        #Net A
        net.addLink( h1_A, s1 )
        net.addLink( h2_A, s1 )
        net.addLink( h3_A, s1 )
        net.addLink( s1, r1 )

        #Net B
        net.addLink( h1_B, s2 )
        net.addLink( h2_B, s2 )
        net.addLink( h3_B, s2, cls=TCLink, delay = '5ms' )
        net.addLink( s2, r1 )

        #Net C
        net.addLink( h1_C, s3 )
        net.addLink( h2_C, s3 )
        net.addLink( h3_C, s3, cls=TCLink, losses = 10)
        net.addLink( s3, r1 )
        s1.start([c1])
        s2.start([c1])
        s3.start([c1])

        CLI(net)

        net.stop()


