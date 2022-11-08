SWITCH_EXE=#PUT THE PATH TO YOUR bvm2 simple_switch_grpc HERE
SWITCH_EXE --log-console  -i 0@veth1 -i 1@veth2 ./telem_switch.json -- --grpc-server-addr 127.0.0.1:9559 --cpu-port 25
