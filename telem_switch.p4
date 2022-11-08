#include <core.p4>
#include <v1model.p4>

#define NUM_QUERIES 8
#define HASH_TABLE_SIZE 65535
#define AGE_OUT_TIME_MS 20000


const bit<16> TYPE_IPV4 = 0x800;
typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<104> fivetuple_bits_t;
typedef bit<NUM_QUERIES> query_flag_t;
typedef bit<32> reg_data_t;
typedef bit<48> timestamp_t;

typedef bit<8> field_id_t;
typedef bit<8> op_id_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_lenght;
    bit<16> checksum;
}

struct fivetuple_t {
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8> proto;
};

struct metadata {
    bit matched;
    query_flag_t queries;
    fivetuple_t ft;
    bit<16> hash;
    bit<104> hash_mask;
    reg_data_t field_data_0;
    reg_data_t field_data_1;
}

header_union port_layer_t {
    tcp_t tcp;
    udp_t udp;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    port_layer_t port_layer;
}

fivetuple_t extract_ft_data(in fivetuple_bits_t ft){
    fivetuple_t ft_res;
    ft_res.src_ip = ft[31:0];
    ft_res.dst_ip = ft[63:32];
    ft_res.src_port = ft[79:64];
    ft_res.dst_port = ft[95:80];
    ft_res.proto = ft[103:96];
    return ft_res;
}

fivetuple_bits_t pack_ft_data(in fivetuple_t ft){
    return ft.proto ++ ft.dst_port ++ ft.src_port ++ ft.dst_ip ++ ft.src_ip;
}

reg_data_t get_field(in field_id_t fid, in headers hdr, in metadata meta){
    reg_data_t ret = 0;
    if(fid == 0){
        ret = 1;
    }
    else if(fid == 1){
        ret = (bit<32>)hdr.ipv4.totalLen;
    }
    else {
        ret = 0;
    }
    return ret;
}

reg_data_t apply_op(in op_id_t op, in reg_data_t old_val, in reg_data_t pkt_val){
    reg_data_t res = 0;
    if(op == 0){//update
        res = pkt_val;
    }
    else if(op == 1){//sum
        res = old_val + pkt_val;
    }
    else if(op == 2){//min
        if(pkt_val < old_val){
            res = pkt_val;
        }
    }
    else if(op == 3){//max
        if(pkt_val > old_val){
            res = pkt_val;
        }
    }
    else if(op == 4){//avg EWMA
        res = (pkt_val >> 1) + (old_val >> 1);
    }
    else{
        res = 0;
    }
    return res;
}

parser TestParser(packet_in packet, 
                  out headers hdr, 
                  inout metadata meta, 
                  inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.port_layer.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.port_layer.udp);
        transition accept;
    }
}

control TestVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}



control TestIngress(inout headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {

    register<fivetuple_bits_t>(HASH_TABLE_SIZE) ft_table;
    register<timestamp_t>(HASH_TABLE_SIZE) ts_table;
    register<reg_data_t>(HASH_TABLE_SIZE) data_table_0;
    register<reg_data_t>(HASH_TABLE_SIZE) data_table_1;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward_to_mac(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; //REMITS FROM SAME PORT
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward_to_mac;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action flag_applicable_queries(query_flag_t queries, bit<104> hash_mask) {
        meta.queries = queries;
        meta.matched = 1;
        if(hdr.port_layer.tcp.isValid()){
            meta.ft  = { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.port_layer.tcp.src_port, hdr.port_layer.tcp.dst_port, hdr.ipv4.protocol};
        }
        else if(hdr.port_layer.udp.isValid()){
            meta.ft  = { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.port_layer.udp.src_port, hdr.port_layer.udp.dst_port, hdr.ipv4.protocol};
        }
        else {
            meta.ft = { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 0, 0, hdr.ipv4.protocol};
        }
        fivetuple_bits_t ft_bits = pack_ft_data(meta.ft);
        hash(meta.hash, HashAlgorithm.crc16, (bit<16>)0, { ft_bits & hash_mask }, (bit<16>)HASH_TABLE_SIZE);
        meta.hash_mask = hash_mask;
    }

    action no_match() {
        meta.matched = 0;
    }


    table filter_match {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.port_layer.udp.src_port: ternary;
            hdr.port_layer.udp.dst_port: ternary;
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            flag_applicable_queries;
            no_match;
        }
        size = 512;
        default_action = no_match();
    }

    action get_field_0(field_id_t fid){
        meta.field_data_0 = get_field(fid, hdr, meta);
    }

    action get_field_1(field_id_t fid){
        meta.field_data_1 = get_field(fid, hdr, meta);
    }

    table unpack_match_0 {
        key = {
            meta.queries : ternary;
        }
        actions = {
            get_field_0;
            NoAction;
        }
        default_action = NoAction;
        size = NUM_QUERIES;
    }

    table unpack_match_1 {
        key = {
            meta.queries : ternary;
        }
        actions = {
            get_field_1;
            NoAction;
        }
        default_action = NoAction;
        size = NUM_QUERIES;
    }

    action apply_op_0(bit<8> op) {
        fivetuple_bits_t ft_bits;
        timestamp_t last_ts;
        reg_data_t data;
        ft_table.read(ft_bits, (bit<32>)meta.hash);
        ts_table.read(last_ts, (bit<32>)meta.hash);
        data_table_0.read(data, (bit<32>)meta.hash);

        fivetuple_bits_t pkt_ft_bits = pack_ft_data(meta.ft) & meta.hash_mask;
        timestamp_t pkt_ts = standard_metadata.ingress_global_timestamp;

        if(ft_bits == (fivetuple_bits_t)0){
            ft_bits = pkt_ft_bits;
            data = 0;
        }

        if((pkt_ts - last_ts) > AGE_OUT_TIME_MS && ft_bits != pkt_ft_bits){
            ft_bits = pkt_ft_bits;
            data = 0;
        }

        data = apply_op(op, data, meta.field_data_0);

        data_table_0.write((bit<32>)meta.hash, data);
        ft_table.write((bit<32>)meta.hash, pkt_ft_bits);
        ts_table.write((bit<32>)meta.hash, pkt_ts);
    }

    action apply_op_1(bit<8> op) {
        fivetuple_bits_t ft_bits;
        timestamp_t last_ts;
        reg_data_t data;
        ft_table.read(ft_bits, (bit<32>)meta.hash);
        ts_table.read(last_ts, (bit<32>)meta.hash);
        data_table_1.read(data, (bit<32>)meta.hash);

        fivetuple_bits_t pkt_ft_bits = pack_ft_data(meta.ft) & meta.hash_mask;
        timestamp_t pkt_ts = standard_metadata.ingress_global_timestamp;

        if(ft_bits == (fivetuple_bits_t)0){
            ft_bits = pkt_ft_bits;
            data = 0;
        }

        if((pkt_ts - last_ts) > AGE_OUT_TIME_MS && ft_bits != pkt_ft_bits){
            ft_bits = pkt_ft_bits;
            data = 0;
        }

        data = apply_op(op, data, meta.field_data_1);

        data_table_1.write((bit<32>)meta.hash, data);
        ft_table.write((bit<32>)meta.hash, ft_bits);
        ts_table.write((bit<32>)meta.hash, pkt_ts);
    }

    table reduction_match_0 {
        key = {
            meta.queries : ternary;
        }
        actions = {
            apply_op_0;
            NoAction;
        }
        size = NUM_QUERIES;
        default_action = NoAction;
    }

    table reduction_match_1 {
        key = {
            meta.queries : ternary;
        }
        actions = {
            apply_op_1;
            NoAction;
        }
        size = NUM_QUERIES;
        default_action = NoAction;
    }

    
    apply {
        filter_match.apply();
        unpack_match_0.apply();
        unpack_match_1.apply();
        @atomic{ reduction_match_0.apply(); }
        @atomic{ reduction_match_1.apply(); }
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
        }
    }
}

control TestEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata){
    apply { }
}

control TestDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.port_layer.tcp);
        packet.emit(hdr.port_layer.udp);
    }
}

control TestComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

V1Switch(
    TestParser(),
    TestVerifyChecksum(),
    TestIngress(),
    TestEgress(),
    TestComputeChecksum(),
    TestDeparser()
    
) main;