from datetime import datetime
import reverse_parse_fields
LOG_SHOW_FILEPATH= "/dev/fw_log"
LOG_CLEAR_FILEPATH= "/sys/class/fw/log/reset"
    
def load():
    try:
        print("timestamp\t\tsrc_ip\t\tdst_ip\t\tsrc_port\t\tdst_port\t\tprotocol\t\taction\t\treason\t\tcount")
        with open(LOG_SHOW_FILEPATH, "rb") as log_show_file:
            validation_bit = log_show_file.read(1)[0]
            while validation_bit==1:
                log = log_show_file.read(23)
                print(reverse_parse_fields.timestamp(log[:4]), reverse_parse_fields.ip(log[6:10]), reverse_parse_fields.ip(log[10:14]), 
                reverse_parse_fields.port(log[14:16]), reverse_parse_fields.port(log[16:18]), reverse_parse_fields.protocol(log[4]), 
                reverse_parse_fields.action(log[5]), reverse_parse_fields.reason(log[18]), reverse_parse_fields.count(log[19:23]), 
                sep="\t\t")
                validation_bit = log_show_file.read(1)[0]
        return True
    except Exception as e:
        return False

def clear():
    try:
        with open(LOG_CLEAR_FILEPATH, "w") as log_clear_file:
            log_clear_file.write("0")
        return True
    except (Exception, ):
        return False
