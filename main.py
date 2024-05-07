import sys
import rules_functions
import log_functions
import conn_functions


def show_rules():
    if not rules_functions.show():
        print("ERROR: failed to show rules table")


def load_rules(rules_file_path):
    if not rules_functions.load(rules_file_path):
        print("ERROR: failed to load rules table")


def log_show():
    if not log_functions.load():
        print("ERROR: failed to show log")


def conn_show():
    if not conn_functions.load():
        print("ERROR: failed to show connection table")


def log_clear():
    if not log_functions.clear():
        print("ERROR: failed to clear log")


if __name__ == "__main__":
    # Check the number of arguments
    if len(sys.argv) < 2:
        print("should get at least one argument")
        sys.exit(1)
    option = sys.argv[1]
    if option == "show_rules":
        show_rules()
    elif option == "load_rules":
        if len(sys.argv) < 3:
            print("load rules should have an argument with path to file")
            sys.exit(1)
        rules_file_path = sys.argv[2]
        load_rules(rules_file_path)
    elif option == "show_log":
        log_show()
    elif option == "clear_log":
        log_clear()
    elif option == "show_conns":
        conn_show()
    else:
        print("Invalid argument. Choose from: show_rules, load_rules, show_log, clear_log, show_conns")
