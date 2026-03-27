def parse_snort_log(log_line):

    parts = log_line.split()

    return {
        "timestamp": parts[0],
        "src_ip": parts[2],
        "dest_ip": parts[4],
        "attack_type": parts[1]
    }