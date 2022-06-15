# VR
Network Virtualization class 
　

## Running TP1 Exercise 1 (layer 2 switch)

Start topology with mininet:

```sudo mn --custom VR/topology/tp1_ex1_topology.py --topo tp1_ex1_topo --mac --controller=remote```

Start layer 2 controller:

```ryu-manager VR/switches/tp1_ex1_controller.py```

## Running TP1 Exercise 2 (layer 3 switch)

Start topology with mininet:

```sudo python3 VR/topology/tp1_ex2_topology.py```

Start layer 2 controller:

```ryu-manager VR/switches/tp1_ex1_controller.py```

Start layer 3 controller:

```ryu-manager VR/switches/tp1_ex2_controller.py --ofp-tcp-listen-port 6655```
