LOG_SHOW_FILEPATH= "/dev/fw_log"
LOG_CLEAR_FILEPATH= "/sys/class/fw/log/reset"


def show():
    return


def clear():
    with open(LOG_CLEAR_FILEPATH, "r") as log_clear_file:
        log_clear_file.write("0")
        return True
    return False
