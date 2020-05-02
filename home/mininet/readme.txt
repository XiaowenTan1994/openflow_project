1.put all controller at /home/mininet/pox/pox/misc/
2.put all topology files at /home/mininet/mininet/custom/
3.start a terminal and run command "./pox.py log.level --DEBUG misc.{controller file name}" at /home/mininet/pox
4.start another terminal and run command "sudo mn --custom {topology file name}.py --topo mytopo --mac --controller remote" at /home/mininet/mininet/custom