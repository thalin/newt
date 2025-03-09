"""
Sample updown script for Newt proxy
Usage: update.py <action> <protocol> <target>

Parameters:
- action: 'add' or 'remove'
- protocol: 'tcp' or 'udp'
- target: the target address in format 'host:port'

If the action is 'add', the script can return a modified target that
will be used instead of the original.
"""

import sys
import logging
import json
from datetime import datetime

# Configure logging
LOG_FILE = "/tmp/newt-updown.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_event(action, protocol, target):
    """Log each event to a file for auditing purposes"""
    timestamp = datetime.now().isoformat()
    event = {
        "timestamp": timestamp,
        "action": action,
        "protocol": protocol,
        "target": target
    }
    logging.info(json.dumps(event))

def handle_add(protocol, target):
    """Handle 'add' action"""
    logging.info(f"Adding {protocol} target: {target}")
    
def handle_remove(protocol, target):
    """Handle 'remove' action"""
    logging.info(f"Removing {protocol} target: {target}")
    # For remove action, no return value is expected or used
    
def main():
    # Check arguments
    if len(sys.argv) != 4:
        logging.error(f"Invalid arguments: {sys.argv}")
        sys.exit(1)
    
    action = sys.argv[1]
    protocol = sys.argv[2]
    target = sys.argv[3]
    
    # Log the event
    log_event(action, protocol, target)
    
    # Handle the action
    if action == "add":
        new_target = handle_add(protocol, target)
        # Print the new target to stdout (if empty, no change will be made)
        if new_target and new_target != target:
            print(new_target)
    elif action == "remove":
        handle_remove(protocol, target)
    else:
        logging.error(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        sys.exit(1)