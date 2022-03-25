from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo( Topo ):
    "Topology Exercise 2"

    def build( self ):
        "Create custom topo."
        inf("*** CREATING NETWORK ***")

        net = Mininet(r)

        # Add hosts and switches
        h1_A = self.addHost( 'h1_A', ip = '192.168.1.1/24' )   # Host 1 Net A
        h2_A = self.addHost( 'h2_A', ip = '192.168.1.2/24' )   # Host 2 Net A
        h3_A = self.addHost( 'h3_A', ip = '192.168.1.3/24' )   # Host 3 Net A
        h1_B = self.addHost( 'h1_B', ip = '192.168.2.1/24' )   # Host 1 Net B
        h2_B = self.addHost( 'h2_B', ip = '192.168.2.2/24'  )   # Host 2 Net B
        h3_B = self.addHost( 'h3_B', ip = '192.168.2.3/24'  )   # Host 3 Net B
        h1_C = self.addHost( 'h1_C', ip = '192.168.3.1/24'  )   # Host 1 Net C
        h2_C = self.addHost( 'h2_C', ip = '192.168.3.2/24'  )   # Host 2 Net C
        h3_C = self.addHost( 'h3_C', ip = '192.168.3.3/24'  )   # Host 3 Net C
        s1 = self.addSwitch( 's1' )     # L2 Switch Net A (no ip)
        s2 = self.addSwitch( 's2' )     # L2 Switch Net B (no ip)
        s3 = self.addSwitch( 's3' )     # L2 Switch Net C (no ip)
        r1 = self.addSwitch( 'r1' )     # L3 Switch
        


        # Add links
        #Net A
        self.addLink( h1_A, s1 )
        self.addLink( h2_A, s1 )
        self.addLink( h3_A, s1 )
        self.addLink( s1, r1 )

        #Net B
        self.addLink( h1_B, s2 )
        self.addLink( h2_B, s2 )
        self.addLink( h3_B, s2, cls=TCLink, delay = '5ms' )
        self.addLink( s2, r1 )

        #Net C
        self.addLink( h1_C, s3 )
        self.addLink( h2_C, s3 )
        self.addLink( h3_C, s3, cls=TCLink, losses = 10)
        self.addLink( s3, r1 )


topos = { 'mytopo': ( lambda: MyTopo() ) }