# VR
Network Virtualization class 


## Running TP1 Exercise 1 (layer 2 switch)

Start topology with mininet:

```sudo python3 topology/topology_tp1_ex1.py```

Start layer 2 controller:

```ryu-manager switches/controller_tp1_ex1_layer2.py```

## Running TP1 Exercise 2 (layer 3 switch)

Start topology with mininet:

```sudo python3 topology/topology_tp1_ex2.py```

Start layer 2 controller:

```ryu-manager switches/controller_tp1_ex1_layer2.py```

Start layer 3 controller:

```ryu-manager switches/controller_tp1_ex2_layer3.py --ofp-tcp-listen-port 6655```
