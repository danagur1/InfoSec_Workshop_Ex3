import struct
LOG_SHOW_FILEPATH= "/dev/fw_log"
LOG_CLEAR_FILEPATH= "/sys/class/fw/log/reset"

def parse_timestamp(bytes_timestamp):
    timestamp = struct.unpack(">IQ", bytes_timestamp)

def load():
    try:
        with open(LOG_SHOW_FILEPATH, "rb") as log_show_file:
            #test:
            validation_bit = log_show_file.read(1)[0]
            while validation_bit==1:
                print(log_show_file.read(13))
                validation_bit = log_show_file.read(1)
        return True
    except (Exception, ):
        return False

def clear():
    try:
        with open(LOG_CLEAR_FILEPATH, "w") as log_clear_file:
            log_clear_file.write("0")
        return True
    except (Exception, ):
        return False
