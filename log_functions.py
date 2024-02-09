LOG_SHOW_FILEPATH= "/dev/fw_log"
LOG_CLEAR_FILEPATH= "/sys/class/fw/log/reset"


def load():
    with open(LOG_SHOW_FILEPATH, "w") as log_show_file:
        #test:
        print(log_show_file.readlines())


def clear():
    with open(LOG_CLEAR_FILEPATH, "w") as log_clear_file:
        log_clear_file.write("0")
        return True
    return False
